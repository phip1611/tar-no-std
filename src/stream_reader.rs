// SPDX-License-Identifier: MIT

//! Module for [`TarStreamReader`], which reads a Tar archive from a
//! [`BlockSource`] one block at a time.

use crate::archive::CorruptDataError;
use crate::header::PosixHeader;
use crate::stream::{StreamEvent, TarStreamParser};
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, POSIX_1003_MAX_FILENAME_LEN};
use core::fmt::{Debug, Display, Formatter};
use core::{error, fmt};

/// Source of 512-byte blocks for [`TarStreamReader`], such as a file, a flash
/// device, or a network stream.
///
/// It is implemented for closures with the same signature as
/// [`BlockSource::read_block`].
///
/// # Examples
///
/// A type that implements the trait, here a mock of a flash device that holds
/// the archive:
///
/// ```rust
/// use tar_no_std::{BlockSource, TarStreamReader};
///
/// struct Flash {
///     data: &'static [u8],
///     offset: usize,
/// }
///
/// #[derive(Debug)]
/// struct PartialBlock;
///
/// impl BlockSource for Flash {
///     type Error = PartialBlock;
///
///     fn read_block(
///         &mut self,
///         buf: &mut [u8; 512],
///     ) -> Result<bool, PartialBlock> {
///         match self.data.get(self.offset..self.offset + 512) {
///             Some(block) => {
///                 buf.copy_from_slice(block);
///                 self.offset += 512;
///                 Ok(true)
///             }
///             None if self.offset == self.data.len() => Ok(false),
///             None => Err(PartialBlock),
///         }
///     }
/// }
///
/// let flash = Flash {
///     data: include_bytes!("../tests/gnu_tar_default.tar"),
///     offset: 0,
/// };
/// let mut reader = TarStreamReader::new(flash);
/// let entry = reader.next_entry().unwrap().unwrap();
/// assert_eq!(entry.filename().as_str(), Ok("bye_world_513b.txt"));
/// assert_eq!(entry.size(), 513);
/// ```
///
/// A closure, here one that reads from a [`std::io::Read`] implementation
/// such as a file:
///
/// ```rust
/// use std::io::{ErrorKind, Read};
/// use tar_no_std::TarStreamReader;
///
/// let mut file: &[u8] = include_bytes!("../tests/gnu_tar_default.tar");
/// let mut reader = TarStreamReader::new(|buf: &mut [u8; 512]| {
///     match file.read_exact(buf) {
///         Ok(()) => Ok(true),
///         Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(false),
///         Err(error) => Err(error),
///     }
/// });
///
/// let mut count = 0;
/// while let Some(_entry) = reader.next_entry().unwrap() {
///     count += 1;
/// }
/// assert_eq!(count, 3);
/// ```
///
/// [`std::io::Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
pub trait BlockSource {
    /// Error returned by the source.
    type Error;

    /// Fills `buf` with the next block of the archive.
    ///
    /// Returns `Ok(false)` if the source has no more blocks.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read.
    fn read_block(&mut self, buf: &mut [u8; BLOCKSIZE]) -> Result<bool, Self::Error>;
}

impl<E, F> BlockSource for F
where
    F: FnMut(&mut [u8; BLOCKSIZE]) -> Result<bool, E>,
{
    type Error = E;

    fn read_block(&mut self, buf: &mut [u8; BLOCKSIZE]) -> Result<bool, E> {
        self(buf)
    }
}

/// Error returned by [`TarStreamReader`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamError<E> {
    /// The [`BlockSource`] returned an error.
    Source(E),
    /// The archive is invalid.
    Corrupt(CorruptDataError),
}

impl<E> From<CorruptDataError> for StreamError<E> {
    fn from(error: CorruptDataError) -> Self {
        Self::Corrupt(error)
    }
}

impl<E: Display> Display for StreamError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "cannot read the next block: {error}"),
            Self::Corrupt(error) => Display::fmt(error, f),
        }
    }
}

impl<E: error::Error> error::Error for StreamError<E> {}

/// Whether [`TarStreamReader`] can read more blocks from its source.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    /// The terminator was not read yet.
    Reading,
    /// The terminator was read, so the source is not read anymore.
    End,
    /// The archive is invalid, and this error is returned by every next call.
    Failed(CorruptDataError),
}

/// Reads a Tar archive from a [`BlockSource`], one block at a time.
///
/// Unlike [`TarArchiveRef`], the archive does not need to be in memory: the
/// reader only keeps the current block, the header and the filename of the
/// current file, and the parser state, about 1.6 KiB. It validates the archive
/// like [`TarArchiveRef::new`] does and, like [`TarArchiveRef::entries`], only
/// reports regular files.
///
/// Payload that was not read is skipped by the next call to
/// [`TarStreamReader::next_entry`].
///
/// Once the archive was found invalid, the reader keeps returning the same
/// error. If the source returns an error, the block is not consumed, so the
/// call can be retried if the source supports it.
///
/// # Example
///
/// ```rust
/// use tar_no_std::TarStreamReader;
///
/// let archive = include_bytes!("../tests/gnu_tar_default.tar");
/// let mut blocks = archive.chunks_exact(512);
/// let mut reader = TarStreamReader::new(|buf: &mut [u8; 512]| {
///     let Some(block) = blocks.next() else {
///         return Ok::<_, ()>(false);
///     };
///     buf.copy_from_slice(block);
///     Ok(true)
/// });
///
/// let mut buf = [0; 64];
/// while let Some(mut entry) = reader.next_entry().unwrap() {
///     println!("{:?} ({} bytes)", entry.filename(), entry.size());
///     loop {
///         let n = entry.read_payload(&mut buf).unwrap();
///         if n == 0 {
///             break;
///         }
///         println!("  {:?}", &buf[..n]);
///     }
/// }
/// ```
///
/// [`TarArchiveRef`]: crate::TarArchiveRef
/// [`TarArchiveRef::new`]: crate::TarArchiveRef::new
/// [`TarArchiveRef::entries`]: crate::TarArchiveRef::entries
pub struct TarStreamReader<S> {
    /// Source of the blocks.
    source: S,
    /// Validates the blocks and tracks the position in the archive.
    parser: TarStreamParser,
    /// Whether more blocks can be read.
    state: State,
    /// Last block read from the source.
    block: [u8; BLOCKSIZE],
    /// Header of the current file.
    header: [u8; BLOCKSIZE],
    /// Filename of the current file, as reported by [`StreamEvent::Entry`].
    ///
    /// [`TarStreamReader::next_entry`] sets it for each file. It is a
    /// dedicated field, as the parser may take the filename from entries
    /// before the header. [`PosixHeader::filename`] of `header` is then
    /// incomplete and must not be used.
    filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
    /// Size of the current file in bytes.
    size: usize,
    /// Start of the unread payload bytes in `block`.
    pos: usize,
    /// End of the payload bytes in `block`.
    len: usize,
    /// Payload bytes of the current file that are not read from the source
    /// yet.
    remaining: usize,
}

impl<S> Debug for TarStreamReader<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TarStreamReader")
            .field("parser", &self.parser)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<S: BlockSource> TarStreamReader<S> {
    /// Creates a reader that reads the archive from `source`.
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            source,
            parser: TarStreamParser::new(),
            state: State::Reading,
            block: [0; BLOCKSIZE],
            header: [0; BLOCKSIZE],
            filename: TarFormatString::new([0; POSIX_1003_MAX_FILENAME_LEN]),
            size: 0,
            pos: 0,
            len: 0,
            remaining: 0,
        }
    }

    /// Returns the next regular file of the archive, or `None` once the
    /// terminator was read.
    ///
    /// Payload of the previous file that was not read is skipped.
    ///
    /// # Errors
    /// Returns [`StreamError::Source`] if the source cannot be read and
    /// [`StreamError::Corrupt`] if the archive is invalid or incomplete.
    pub fn next_entry(&mut self) -> Result<Option<StreamEntry<'_, S>>, StreamError<S::Error>> {
        if self.state == State::End {
            return Ok(None);
        }
        while self.remaining > 0 {
            self.next_block()?;
        }
        loop {
            match self.next_block()? {
                Some(StreamEvent::Entry { filename, size, .. }) => {
                    self.header = self.block;
                    self.filename = filename;
                    self.size = size;
                    self.remaining = size;
                    self.pos = 0;
                    self.len = 0;
                    return Ok(Some(StreamEntry { reader: self }));
                }
                Some(StreamEvent::End) => return Ok(None),
                Some(StreamEvent::Data { .. }) | None => {}
            }
        }
    }

    /// Reads the next block from the source and parses it.
    fn next_block(&mut self) -> Result<Option<StreamEvent<'_>>, StreamError<S::Error>> {
        if let State::Failed(error) = self.state {
            return Err(error.into());
        }
        let has_block = self
            .source
            .read_block(&mut self.block)
            .map_err(StreamError::Source)?;
        let event = if has_block {
            self.parser.parse_block(&self.block)
        } else {
            // The source is not read after the terminator, so the archive is
            // incomplete and `finish()` returns an error.
            Err(self
                .parser
                .finish()
                .err()
                .unwrap_or(CorruptDataError::MissingTerminator))
        };
        match event {
            Ok(Some(StreamEvent::Data { data, remaining })) => {
                self.pos = 0;
                self.len = data.len();
                self.remaining = remaining;
            }
            Ok(Some(StreamEvent::End)) => self.state = State::End,
            Ok(Some(StreamEvent::Entry { .. }) | None) => {}
            Err(error) => self.state = State::Failed(error),
        }
        event.map_err(StreamError::Corrupt)
    }
}

/// Regular file returned by [`TarStreamReader::next_entry`].
pub struct StreamEntry<'a, S> {
    /// Reader that holds the header and the payload position of the file.
    reader: &'a mut TarStreamReader<S>,
}

impl<S> Debug for StreamEntry<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamEntry")
            .field("filename", &self.filename().as_str())
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

impl<S> StreamEntry<'_, S> {
    /// Returns the [`PosixHeader`] of the file.
    #[must_use]
    pub const fn posix_header(&self) -> &PosixHeader {
        PosixHeader::from_block(&self.reader.header, 0)
    }

    /// Filename of the file, including the ustar prefix or the GNU long name
    /// if there is one.
    #[must_use]
    pub const fn filename(&self) -> TarFormatString<POSIX_1003_MAX_FILENAME_LEN> {
        self.reader.filename
    }

    /// Size of the file in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.reader.size
    }
}

impl<S: BlockSource> StreamEntry<'_, S> {
    /// Reads payload bytes of the file into `buf` and returns how many bytes
    /// were read, like [`std::io::Read::read`].
    ///
    /// Returns `0` once the whole payload was read, or if `buf` is empty.
    ///
    /// # Errors
    /// Returns [`StreamError::Source`] if the source cannot be read and
    /// [`StreamError::Corrupt`] if the archive ends inside the payload.
    ///
    /// [`std::io::Read::read`]: https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
    pub fn read_payload(&mut self, buf: &mut [u8]) -> Result<usize, StreamError<S::Error>> {
        let reader = &mut *self.reader;
        if reader.pos == reader.len {
            if reader.remaining == 0 || buf.is_empty() {
                return Ok(0);
            }
            reader.next_block()?;
        }
        let n = buf.len().min(reader.len - reader.pos);
        buf[..n].copy_from_slice(&reader.block[reader.pos..reader.pos + n]);
        reader.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TarArchiveRef;
    use core::cell::Cell;
    use core::convert::Infallible;
    use std::string::{String, ToString};
    use std::vec::Vec;

    type Files = Vec<(String, Vec<u8>)>;

    fn source(data: &[u8]) -> impl FnMut(&mut [u8; BLOCKSIZE]) -> Result<bool, Infallible> + '_ {
        let mut blocks = data.chunks_exact(BLOCKSIZE);
        move |buf| {
            let Some(block) = blocks.next() else {
                return Ok(false);
            };
            buf.copy_from_slice(block);
            Ok(true)
        }
    }

    fn read_files<S: BlockSource>(
        reader: &mut TarStreamReader<S>,
        chunk_size: usize,
    ) -> Result<Files, StreamError<S::Error>> {
        let mut files = Vec::new();
        let mut buf = std::vec![0; chunk_size];
        while let Some(mut entry) = reader.next_entry()? {
            let filename = entry.filename().as_str().unwrap().to_string();
            let mut data = Vec::new();
            loop {
                let n = entry.read_payload(&mut buf)?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            assert_eq!(data.len(), entry.size());
            files.push((filename, data));
        }
        Ok(files)
    }

    fn archive_entries(data: &[u8]) -> Files {
        TarArchiveRef::new(data)
            .unwrap()
            .entries()
            .map(|entry| {
                (
                    entry.filename().as_str().unwrap().to_string(),
                    entry.data().to_vec(),
                )
            })
            .collect()
    }

    const ARCHIVES: [&[u8]; 13] = [
        include_bytes!("../tests/gnu_tar_default.tar"),
        include_bytes!("../tests/gnu_tar_default_with_dir.tar"),
        include_bytes!("../tests/gnu_tar_gnu.tar"),
        include_bytes!("../tests/gnu_tar_oldgnu.tar"),
        include_bytes!("../tests/gnu_tar_pax.tar"),
        include_bytes!("../tests/gnu_tar_posix.tar"),
        include_bytes!("../tests/gnu_tar_ustar.tar"),
        include_bytes!("../tests/gnu_tar_ustar_deep.tar"),
        include_bytes!("../tests/gnu_tar_ustar_long.tar"),
        include_bytes!("../tests/gnu_tar_v7.tar"),
        include_bytes!("../tests/gnu_tar_gnu_long_names.tar"),
        include_bytes!("../tests/mac_tar_ustar_with_dir.tar"),
        include_bytes!("../tests/weird_fuzzing_tarballs.tar"),
    ];

    #[test]
    fn test_reader_matches_archive_entries() {
        for data in ARCHIVES {
            for chunk_size in [1, 7, BLOCKSIZE, 2 * BLOCKSIZE] {
                let mut reader = TarStreamReader::new(source(data));
                assert_eq!(
                    read_files(&mut reader, chunk_size),
                    Ok(archive_entries(data))
                );
                assert!(reader.next_entry().unwrap().is_none());
            }
        }
    }

    #[test]
    fn test_unread_payload_is_skipped() {
        let data = include_bytes!("../tests/gnu_tar_default_with_dir.tar");
        let mut reader = TarStreamReader::new(source(data));
        let mut filenames = Vec::new();
        let mut first_byte = [0];
        while let Some(mut entry) = reader.next_entry().unwrap() {
            filenames.push(entry.filename().as_str().unwrap().to_string());
            // Read a single byte at most, and leave the rest of the payload.
            entry.read_payload(&mut first_byte).unwrap();
        }
        let expected = archive_entries(data)
            .into_iter()
            .map(|(filename, _)| filename)
            .collect::<Vec<_>>();
        assert_eq!(filenames, expected);
    }

    #[test]
    fn test_entry_reports_header() {
        let data = include_bytes!("../tests/gnu_tar_default_with_dir.tar");
        let mut reader = TarStreamReader::new(source(data));
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.filename().as_str(), Ok("tests/hello_world.txt"));
        assert_eq!(entry.size(), 12);
        assert_eq!(
            entry.posix_header().size.as_number::<usize>(),
            Ok(entry.size())
        );
    }

    #[test]
    fn test_rejects_empty_source() {
        let mut reader = TarStreamReader::new(source(&[]));
        assert_eq!(
            reader.next_entry().err(),
            Some(StreamError::Corrupt(CorruptDataError::EmptyArchive))
        );
    }

    #[test]
    fn test_rejects_truncated_payload() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut reader = TarStreamReader::new(source(&data[..2 * BLOCKSIZE]));
        let mut entry = reader.next_entry().unwrap().unwrap();
        let mut buf = [0; BLOCKSIZE];
        assert_eq!(entry.read_payload(&mut buf), Ok(BLOCKSIZE));
        assert_eq!(
            entry.read_payload(&mut buf),
            Err(StreamError::Corrupt(
                CorruptDataError::PayloadExtendsBeyondArchive { block_index: 0 }
            ))
        );
    }

    #[test]
    fn test_rejects_missing_terminator() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let end_of_entries = data[..data.len() - 2 * BLOCKSIZE]
            .chunks_exact(BLOCKSIZE)
            .rposition(|block| block.iter().any(|&b| b != 0))
            .unwrap()
            + 1;
        let mut reader = TarStreamReader::new(source(&data[..end_of_entries * BLOCKSIZE]));
        assert_eq!(
            read_files(&mut reader, BLOCKSIZE),
            Err(StreamError::Corrupt(CorruptDataError::MissingTerminator))
        );
    }

    #[test]
    fn test_errors_are_sticky() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let reads = Cell::new(0);
        let mut blocks = data.chunks_exact(BLOCKSIZE);
        let mut reader = TarStreamReader::new(|buf: &mut [u8; BLOCKSIZE]| {
            reads.set(reads.get() + 1);
            // The input ends after the first header, then goes on.
            if reads.get() == 2 {
                return Ok::<_, Infallible>(false);
            }
            let Some(block) = blocks.next() else {
                return Ok(false);
            };
            buf.copy_from_slice(block);
            Ok(true)
        });
        let error =
            StreamError::Corrupt(CorruptDataError::PayloadExtendsBeyondArchive { block_index: 0 });
        let mut entry = reader.next_entry().unwrap().unwrap();
        let mut buf = [0; BLOCKSIZE];
        assert_eq!(entry.read_payload(&mut buf), Err(error));
        assert_eq!(entry.read_payload(&mut buf), Err(error));
        assert_eq!(reader.next_entry().err(), Some(error));
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn test_reports_source_errors() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut blocks = data.chunks_exact(BLOCKSIZE).take(2);
        let mut reader = TarStreamReader::new(|buf: &mut [u8; BLOCKSIZE]| {
            let Some(block) = blocks.next() else {
                return Err("device unplugged");
            };
            buf.copy_from_slice(block);
            Ok(true)
        });
        assert_eq!(
            read_files(&mut reader, BLOCKSIZE),
            Err(StreamError::Source("device unplugged"))
        );
    }

    #[test]
    fn test_does_not_read_after_end() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let reads = Cell::new(0);
        let mut blocks = data.chunks_exact(BLOCKSIZE);
        let mut reader = TarStreamReader::new(|buf: &mut [u8; BLOCKSIZE]| {
            reads.set(reads.get() + 1);
            let Some(block) = blocks.next() else {
                return Ok::<_, Infallible>(false);
            };
            buf.copy_from_slice(block);
            Ok(true)
        });
        while reader.next_entry().unwrap().is_some() {}
        let reads_until_end = reads.get();
        assert!(reader.next_entry().unwrap().is_none());
        assert_eq!(reads.get(), reads_until_end);
    }

    #[test]
    fn test_reader_rejects_weird_fuzzing_tarballs() {
        let main_tarball =
            TarArchiveRef::new(include_bytes!("../tests/weird_fuzzing_tarballs.tar")).unwrap();
        let mut checked = 0;
        for fuzzing_input in main_tarball.entries() {
            let data = fuzzing_input.data();
            if data.len() % BLOCKSIZE == 0 {
                let mut reader = TarStreamReader::new(source(data));
                assert!(read_files(&mut reader, BLOCKSIZE).is_err());
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}
