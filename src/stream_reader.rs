// SPDX-License-Identifier: MIT

//! Module for [`TarStreamReader`], which reads a Tar archive from a
//! [`BlockSource`] one block at a time.

use crate::archive::CorruptDataError;
use crate::header::{PosixHeader, TypeFlag};
use crate::stream::{StreamEvent, TarStreamParser};
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, POSIX_1003_MAX_FILENAME_LEN};
use core::error;
use core::fmt::{self, Display, Formatter};

/// Source of 512-byte blocks for [`TarStreamReader`], such as a file, a flash
/// device, or a network stream.
///
/// It is implemented for closures with the same signature as
/// [`BlockSource::read_block`].
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

/// What a block turned out to be, without borrowing it.
enum Block {
    Entry {
        block_index: usize,
        payload_size: usize,
    },
    Data {
        len: usize,
        remaining: usize,
    },
    End,
    Skipped,
}

/// Reads a Tar archive from a [`BlockSource`], one block at a time.
///
/// Unlike [`TarArchiveRef`], the archive does not need to be in memory: the
/// reader only keeps the current block and the header of the current file.
/// It uses [`TarStreamParser`] internally, so it validates the archive in the
/// same way and only reports regular files.
///
/// Payload that was not read is skipped by the next call to
/// [`TarStreamReader::next_entry`].
///
/// If the source returns an error, the block is not consumed, so the call
/// can be retried if the source supports it.
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
///     println!("{:?} ({} bytes)", entry.filename(), entry.payload_size());
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
#[derive(Debug)]
pub struct TarStreamReader<S> {
    source: S,
    parser: TarStreamParser,
    block: [u8; BLOCKSIZE],
    header: [u8; BLOCKSIZE],
    header_block_index: usize,
    payload_size: usize,
    /// Unread payload bytes of the current file in `block[pos..len]`.
    pos: usize,
    len: usize,
    /// Payload bytes of the current file that are not read from the source
    /// yet.
    payload_remaining: usize,
    done: bool,
}

impl<S: BlockSource> TarStreamReader<S> {
    /// Creates a reader that reads the archive from `source`.
    pub const fn new(source: S) -> Self {
        Self {
            source,
            parser: TarStreamParser::new(),
            block: [0; BLOCKSIZE],
            header: [0; BLOCKSIZE],
            header_block_index: 0,
            payload_size: 0,
            pos: 0,
            len: 0,
            payload_remaining: 0,
            done: false,
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
    pub fn next_entry(
        &mut self,
    ) -> Result<Option<StreamReaderEntry<'_, S>>, StreamError<S::Error>> {
        if self.done {
            return Ok(None);
        }
        while self.payload_remaining > 0 {
            let Block::Data { remaining, .. } = self.read_block()? else {
                unreachable!("the parser is inside the payload of a regular file");
            };
            self.payload_remaining = remaining;
        }
        self.pos = 0;
        self.len = 0;
        loop {
            match self.read_block()? {
                Block::Entry {
                    block_index,
                    payload_size,
                } => {
                    self.header = self.block;
                    self.header_block_index = block_index;
                    self.payload_size = payload_size;
                    self.payload_remaining = payload_size;
                    return Ok(Some(StreamReaderEntry { reader: self }));
                }
                Block::End => {
                    self.done = true;
                    return Ok(None);
                }
                Block::Data { .. } | Block::Skipped => {}
            }
        }
    }

    fn read_block(&mut self) -> Result<Block, StreamError<S::Error>> {
        if !self
            .source
            .read_block(&mut self.block)
            .map_err(StreamError::Source)?
        {
            // The parser only accepts the end of the input after the
            // terminator, which is handled by `next_entry`.
            let error = self
                .parser
                .finish()
                .err()
                .unwrap_or(CorruptDataError::MissingTerminator);
            return Err(error.into());
        }
        let block = match self.parser.parse_block(&self.block)? {
            Some(StreamEvent::Entry(entry)) => Block::Entry {
                block_index: entry.block_index(),
                payload_size: entry.payload_size(),
            },
            Some(StreamEvent::Data { bytes, remaining }) => Block::Data {
                len: bytes.len(),
                remaining,
            },
            Some(StreamEvent::End) => Block::End,
            None => Block::Skipped,
        };
        Ok(block)
    }

    const fn posix_header(&self) -> &PosixHeader {
        PosixHeader::from_block(&self.header, 0)
    }
}

/// Regular file returned by [`TarStreamReader::next_entry`].
#[derive(Debug)]
pub struct StreamReaderEntry<'r, S> {
    reader: &'r mut TarStreamReader<S>,
}

impl<S: BlockSource> StreamReaderEntry<'_, S> {
    /// Index of the header block in the archive.
    #[must_use]
    pub const fn block_index(&self) -> usize {
        self.reader.header_block_index
    }

    /// Returns the [`PosixHeader`] of the file.
    #[must_use]
    pub const fn posix_header(&self) -> &PosixHeader {
        self.reader.posix_header()
    }

    /// Type of the file.
    #[must_use]
    pub fn type_flag(&self) -> TypeFlag {
        self.posix_header()
            .typeflag
            .try_to_type_flag()
            .expect("type flag should be valid after successful validation")
    }

    /// Filename of the file, including the ustar prefix if there is one.
    #[must_use]
    pub fn filename(&self) -> TarFormatString<POSIX_1003_MAX_FILENAME_LEN> {
        self.posix_header().filename()
    }

    /// Size of the file in bytes.
    #[must_use]
    pub const fn payload_size(&self) -> usize {
        self.reader.payload_size
    }

    /// Reads payload bytes of the file into `buf` and returns how many bytes
    /// were read, like [`std::io::Read::read`]. Returns `0` once the whole
    /// payload was read, or if `buf` is empty.
    ///
    /// # Errors
    /// Returns [`StreamError::Source`] if the source cannot be read and
    /// [`StreamError::Corrupt`] if the archive ends inside the payload.
    ///
    /// [`std::io::Read::read`]: https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
    pub fn read_payload(&mut self, buf: &mut [u8]) -> Result<usize, StreamError<S::Error>> {
        let reader = &mut *self.reader;
        if reader.pos == reader.len {
            if reader.payload_remaining == 0 || buf.is_empty() {
                return Ok(0);
            }
            let Block::Data { len, remaining } = reader.read_block()? else {
                unreachable!("the parser is inside the payload of a regular file");
            };
            reader.pos = 0;
            reader.len = len;
            reader.payload_remaining = remaining;
        }
        let n = buf.len().min(reader.len - reader.pos);
        buf[..n].copy_from_slice(&reader.block[reader.pos..reader.pos + n]);
        reader.pos += n;
        Ok(n)
    }
}
