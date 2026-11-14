// SPDX-License-Identifier: MIT

//! Module for [`PaxScanner`], which scans the records of PAX extended headers.
//!
//! Both [`TarArchiveRef`] and [`TarStreamParser`] use it, so they apply the
//! same records.
//!
//! [`TarArchiveRef`]: crate::TarArchiveRef
//! [`TarStreamParser`]: crate::TarStreamParser

use crate::POSIX_1003_MAX_FILENAME_LEN;
use crate::archive::CorruptDataError;
use crate::tar_format_types::TarFormatString;

/// Number of bytes of a key that are kept to classify it.
///
/// Longer keys are not of interest.
const KEY_LEN: usize = 16;

/// Filename of an entry, including the ustar prefix or a long name.
type Filename = TarFormatString<POSIX_1003_MAX_FILENAME_LEN>;

/// Reason why the records of a PAX extended header cannot be applied.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PaxError {
    /// The `path` record is longer than [`POSIX_1003_MAX_FILENAME_LEN`] bytes.
    PathTooLong,
}

impl PaxError {
    /// Converts the error for the PAX extended header at `block_index`.
    pub const fn into_corrupt_data_error(self, block_index: usize) -> CorruptDataError {
        match self {
            Self::PathTooLong => CorruptDataError::FilenameTooLong { block_index },
        }
    }
}

/// Key of a record, as far as this crate handles it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Key {
    /// Filename of the next entry.
    Path,
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
/// written to the filename of the next entry. Other records are skipped, and
/// so are malformed records, like before this scanner existed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PaxScanner {
    /// What the next byte belongs to.
    state: State,
    /// First bytes of the key of the current record.
    key: [u8; KEY_LEN],
    /// Length of the key of the current record, which may exceed `KEY_LEN`.
    key_len: usize,
    /// Length of the value of the current `path` record.
    path_len: usize,
}

impl PaxScanner {
    /// Creates a scanner for the payload of a PAX extended header.
    pub const fn new() -> Self {
        Self {
            state: State::Length { len: 0, digits: 0 },
            key: [0; KEY_LEN],
            key_len: 0,
            path_len: 0,
        }
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
                        let key = self.classify();
                        if key == Key::Path {
                            *filename = Some(Filename::new([0; POSIX_1003_MAX_FILENAME_LEN]));
                            self.path_len = 0;
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
    const fn classify(&self) -> Key {
        let key = self.key.split_at(if self.key_len < KEY_LEN {
            self.key_len
        } else {
            KEY_LEN
        });
        match key.0 {
            b"path" => Key::Path,
            _ => Key::Other,
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
    fn scan(records: &[u8], chunk_size: usize) -> (Result<(), PaxError>, Option<Filename>) {
        let mut scanner = PaxScanner::new();
        let mut filename = None;
        let result = records
            .chunks(chunk_size)
            .try_for_each(|chunk| scanner.feed(chunk, &mut filename));
        (result, filename)
    }

    #[test]
    fn test_record_helper() {
        assert_eq!(
            record("mtime", "1633330466.888204366"),
            "30 mtime=1633330466.888204366\n"
        );
    }

    #[test]
    fn test_applies_path_in_any_chunks() {
        let records = record("mtime", "1633330466.888204366")
            + &record("path", "dir/file.txt")
            + &record("size", "513");
        for chunk_size in [1, 2, 7, records.len()] {
            let (result, filename) = scan(records.as_bytes(), chunk_size);
            assert_eq!(result, Ok(()));
            assert_eq!(filename.unwrap().as_str(), Ok("dir/file.txt"));
        }
    }

    #[test]
    fn test_skips_other_records() {
        let (result, filename) = scan(record("mtime", "1").as_bytes(), 3);
        assert_eq!(result, Ok(()));
        assert_eq!(filename, None);
    }

    #[test]
    fn test_rejects_too_long_path() {
        let records = record("path", &"a".repeat(257));
        assert_eq!(scan(records.as_bytes(), 100).0, Err(PaxError::PathTooLong));

        // The longest supported path fills the filename completely.
        let path = "a".repeat(256);
        let (result, filename) = scan(record("path", &path).as_bytes(), 100);
        assert_eq!(result, Ok(()));
        assert_eq!(filename.unwrap().as_str(), Ok(path.as_str()));
    }

    #[test]
    fn test_ignores_malformed_records() {
        for records in [
            &b"x path=abc\n"[..],
            b"5 path=abc\n",
            b"12 path=abcd",
            b"999999999999999999999999 path=abc\n",
        ] {
            let (result, filename) = scan(records, 4);
            assert_eq!(result, Ok(()));
            assert_eq!(filename, None);
        }
    }
}
