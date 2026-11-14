// SPDX-License-Identifier: MIT

//! Module for [`PaxScanner`], which scans the records of PAX extended headers.
//!
//! Both [`TarArchiveRef`] and [`TarStreamParser`] use it, so they apply and
//! reject the same records.
//!
//! [`TarArchiveRef`]: crate::TarArchiveRef
//! [`TarStreamParser`]: crate::TarStreamParser

use crate::POSIX_1003_MAX_FILENAME_LEN;
use crate::archive::CorruptDataError;
use crate::tar_format_types::TarFormatString;

/// Number of bytes of a key that are kept to classify it.
///
/// This fits the longest key prefix of interest, [`SPARSE_KEY_PREFIX`].
const KEY_LEN: usize = 16;

/// Prefix of the keys that GNU tar uses for sparse files in PAX archives.
const SPARSE_KEY_PREFIX: &[u8] = b"GNU.sparse.";

/// Filename of an entry, including the ustar prefix or a long name.
type Filename = TarFormatString<POSIX_1003_MAX_FILENAME_LEN>;

/// Reason why the records of a PAX extended header cannot be applied.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PaxError {
    /// The `path` record is longer than [`POSIX_1003_MAX_FILENAME_LEN`] bytes.
    PathTooLong,
    /// A record cannot be applied, such as the data of a sparse file.
    Unsupported,
}

impl PaxError {
    /// Converts the error for the PAX extended header at `block_index`.
    pub const fn into_corrupt_data_error(self, block_index: usize) -> CorruptDataError {
        match self {
            Self::PathTooLong => CorruptDataError::FilenameTooLong { block_index },
            Self::Unsupported => CorruptDataError::UnsupportedPaxRecord { block_index },
        }
    }
}

/// Key of a record, as far as this crate handles it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Key {
    /// Filename of the next entry.
    Path,
    /// Payload size of the next entry.
    Size,
    /// Any other key, such as `mtime`, whose record is skipped.
    Other,
}

/// Position in the records, i.e. what the next byte belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    /// The decimal length of a record, which counts all of its bytes.
    Length {
        /// Length parsed so far.
        len: usize,
        /// Number of digits parsed so far.
        digits: usize,
    },
    /// The key of a record.
    Key {
        /// Bytes of the record after the next one.
        remaining: usize,
    },
    /// The value of a record, terminated by a newline.
    Value {
        /// Bytes of the record from the next one on.
        remaining: usize,
        /// Key of the record.
        key: Key,
    },
    /// A record is malformed, so the remaining bytes are ignored.
    Invalid,
}

/// Scans the records of a PAX extended header, which have the format
/// `<length> <key>=<value>\n`.
///
/// The records can be passed in chunks of any size. A `path` record is
/// written to the filename of the next entry. The value of a `size` record is
/// kept, so the caller can check that it matches the size in the next header.
/// Records of GNU sparse files, and `path` or `size` records in a global
/// header, are rejected. Other records are skipped, and so are malformed
/// records, like before this scanner existed.
// TODO: Apply `size` records instead of rejecting differing ones, so files
// larger than 8 GiB work on 64-bit targets. This needs both parsers and the
// public header iterator to skip by the PAX size. Sparse files could be
// supported in the streaming API, which can produce the holes as zeros.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PaxScanner {
    /// What the next byte belongs to.
    state: State,
    /// Whether the header applies to all following entries (type `g`).
    global: bool,
    /// First bytes of the key of the current record.
    key: [u8; KEY_LEN],
    /// Length of the key of the current record, which may exceed `KEY_LEN`.
    key_len: usize,
    /// Length of the value of the current `path` record.
    path_len: usize,
    /// Value of the `size` record, or `u64::MAX` if it is not a number.
    size: Option<u64>,
}

impl PaxScanner {
    /// Creates a scanner for the payload of a PAX extended header.
    pub const fn new(global: bool) -> Self {
        Self {
            state: State::Length { len: 0, digits: 0 },
            global,
            key: [0; KEY_LEN],
            key_len: 0,
            path_len: 0,
            size: None,
        }
    }

    /// Returns the value of the `size` record, if there was one.
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// Scans the next bytes of the records.
    ///
    /// A `path` record replaces `filename`.
    ///
    /// # Errors
    /// Returns [`PaxError`] if a record cannot be applied.
    pub fn feed(&mut self, bytes: &[u8], filename: &mut Option<Filename>) -> Result<(), PaxError> {
        let mut i = 0;
        while i < bytes.len() {
            match self.state {
                State::Invalid => return Ok(()),
                State::Length { len, digits } => {
                    let byte = bytes[i];
                    i += 1;
                    self.state = match byte {
                        b'0'..=b'9' => len
                            .checked_mul(10)
                            .and_then(|len| len.checked_add(usize::from(byte - b'0')))
                            .map_or(State::Invalid, |len| State::Length {
                                len,
                                digits: digits + 1,
                            }),
                        // The record needs at least a key, `=`, and `\n`.
                        b' ' if digits > 0 && len > digits + 3 => {
                            self.key_len = 0;
                            State::Key {
                                remaining: len - digits - 2,
                            }
                        }
                        _ => State::Invalid,
                    };
                }
                State::Key { remaining } => {
                    let byte = bytes[i];
                    i += 1;
                    self.state = if byte == b'=' {
                        let key = self.classify()?;
                        if key == Key::Path {
                            *filename = Some(Filename::new([0; POSIX_1003_MAX_FILENAME_LEN]));
                            self.path_len = 0;
                        }
                        if key == Key::Size {
                            self.size = Some(0);
                        }
                        State::Value { remaining, key }
                    } else if remaining > 1 {
                        if let Some(slot) = self.key.get_mut(self.key_len) {
                            *slot = byte;
                        }
                        self.key_len += 1;
                        State::Key {
                            remaining: remaining - 1,
                        }
                    } else {
                        State::Invalid
                    };
                }
                State::Value { remaining, key } => {
                    let len = remaining.min(bytes.len() - i);
                    let chunk = &bytes[i..i + len];
                    i += len;
                    let remaining = remaining - len;
                    // The last byte of a record is the newline.
                    let value = if remaining == 0 {
                        &chunk[..len - 1]
                    } else {
                        chunk
                    };
                    match key {
                        Key::Path => self.push_path(value, filename),
                        Key::Size => self.push_size(value),
                        Key::Other => {}
                    }
                    self.state = if remaining > 0 {
                        State::Value { remaining, key }
                    } else if chunk[len - 1] != b'\n' {
                        // Do not apply a path from a malformed record.
                        if key == Key::Path {
                            *filename = None;
                        }
                        State::Invalid
                    } else if key == Key::Path && self.path_len > POSIX_1003_MAX_FILENAME_LEN {
                        return Err(PaxError::PathTooLong);
                    } else {
                        State::Length { len: 0, digits: 0 }
                    };
                }
            }
        }
        Ok(())
    }

    /// Classifies the key of the current record.
    const fn classify(&self) -> Result<Key, PaxError> {
        let key = self.key.split_at(if self.key_len < KEY_LEN {
            self.key_len
        } else {
            KEY_LEN
        });
        let key = key.0;
        let is_sparse = key.len() >= SPARSE_KEY_PREFIX.len() && starts_with(key, SPARSE_KEY_PREFIX);
        match key {
            _ if is_sparse => Err(PaxError::Unsupported),
            b"path" | b"size" if self.global => Err(PaxError::Unsupported),
            b"path" => Ok(Key::Path),
            b"size" => Ok(Key::Size),
            _ => Ok(Key::Other),
        }
    }

    /// Appends bytes of a `path` value to `filename`.
    fn push_path(&mut self, value: &[u8], filename: &mut Option<Filename>) {
        let bytes = filename
            .as_mut()
            .expect("filename should be set at the start of the path record")
            .as_mut_bytes();
        for &byte in value {
            if let Some(slot) = bytes.get_mut(self.path_len) {
                *slot = byte;
            }
            self.path_len += 1;
        }
    }

    /// Appends digits of a `size` value.
    fn push_size(&mut self, value: &[u8]) {
        for &byte in value {
            self.size = self.size.map(|size| match byte {
                b'0'..=b'9' => size
                    .saturating_mul(10)
                    .saturating_add(u64::from(byte - b'0')),
                _ => u64::MAX,
            });
        }
    }
}

/// Whether `bytes` starts with `prefix`, in a const context.
const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() {
        if bytes[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    /// Returns a record with a correct length.
    fn record(key: &str, value: &str) -> String {
        let len_without_digits = key.len() + value.len() + 3;
        let mut len = len_without_digits + 1;
        while len_without_digits + len.to_string().len() != len {
            len += 1;
        }
        format!("{len} {key}={value}\n")
    }

    /// Scans `records` in chunks of `chunk_size` bytes.
    fn scan(
        records: &[u8],
        chunk_size: usize,
    ) -> (Result<(), PaxError>, Option<Filename>, Option<u64>) {
        let mut scanner = PaxScanner::new(false);
        let mut filename = None;
        let result = records
            .chunks(chunk_size)
            .try_for_each(|chunk| scanner.feed(chunk, &mut filename));
        (result, filename, scanner.size())
    }

    #[test]
    fn test_record_helper() {
        assert_eq!(
            record("mtime", "1633330466.888204366"),
            "30 mtime=1633330466.888204366\n"
        );
    }

    #[test]
    fn test_applies_path_and_size_in_any_chunks() {
        let records = record("mtime", "1633330466.888204366")
            + &record("path", "dir/file.txt")
            + &record("size", "513");
        for chunk_size in [1, 2, 7, records.len()] {
            let (result, filename, size) = scan(records.as_bytes(), chunk_size);
            assert_eq!(result, Ok(()));
            assert_eq!(filename.unwrap().as_str(), Ok("dir/file.txt"));
            assert_eq!(size, Some(513));
        }
    }

    #[test]
    fn test_skips_other_records() {
        let (result, filename, size) = scan(record("mtime", "1").as_bytes(), 3);
        assert_eq!(result, Ok(()));
        assert_eq!(filename, None);
        assert_eq!(size, None);
    }

    #[test]
    fn test_rejects_too_long_path() {
        let records = record("path", &"a".repeat(257));
        assert_eq!(scan(records.as_bytes(), 100).0, Err(PaxError::PathTooLong));

        // The longest supported path fills the filename completely.
        let path = "a".repeat(256);
        let (result, filename, _) = scan(record("path", &path).as_bytes(), 100);
        assert_eq!(result, Ok(()));
        assert_eq!(filename.unwrap().as_str(), Ok(path.as_str()));
    }

    #[test]
    fn test_rejects_sparse_records() {
        let (result, ..) = scan(record("GNU.sparse.major", "1").as_bytes(), 5);
        assert_eq!(result, Err(PaxError::Unsupported));
    }

    #[test]
    fn test_rejects_path_in_global_header() {
        let mut scanner = PaxScanner::new(true);
        let mut filename = None;
        let records = record("path", "abc");
        assert_eq!(
            scanner.feed(records.as_bytes(), &mut filename),
            Err(PaxError::Unsupported)
        );
        // git archive writes a global header with a comment.
        let mut scanner = PaxScanner::new(true);
        let records = record("comment", "abc");
        assert_eq!(scanner.feed(records.as_bytes(), &mut filename), Ok(()));
    }

    #[test]
    fn test_ignores_malformed_records() {
        for records in [
            &b"x path=abc\n"[..],
            b"5 path=abc\n",
            b"12 path=abcd",
            b"999999999999999999999999 path=abc\n",
        ] {
            let (result, filename, size) = scan(records, 4);
            assert_eq!(result, Ok(()));
            assert_eq!(filename, None);
            assert_eq!(size, None);
        }
    }

    #[test]
    fn test_invalid_size_never_matches() {
        assert_eq!(scan(record("size", "1x3").as_bytes(), 4).2, Some(u64::MAX));
    }
}
