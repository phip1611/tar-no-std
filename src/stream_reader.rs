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
/// reader only keeps the current block and the header of the current file,
/// about 1 KiB. It validates the archive like [`TarArchiveRef::new`] does,
/// except that it does not require [`MIN_BLOCK_COUNT`] blocks: two zero
/// blocks are a valid empty archive. Like [`TarArchiveRef::entries`], it
/// only reports regular files.
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
/// [`MIN_BLOCK_COUNT`]: crate::MIN_BLOCK_COUNT
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
    pub fn next_entry(
        &mut self,
    ) -> Result<Option<StreamReaderEntry<'_, S>>, StreamError<S::Error>> {
        if self.state == State::End {
            return Ok(None);
        }
        while self.remaining > 0 {
            self.next_block()?;
        }
        loop {
            match self.next_block()? {
                Some(StreamEvent::Entry { size }) => {
                    self.header = self.block;
                    self.size = size;
                    self.remaining = size;
                    self.pos = 0;
                    self.len = 0;
                    return Ok(Some(StreamReaderEntry { reader: self }));
                }
                Some(StreamEvent::End) => return Ok(None),
                Some(StreamEvent::Data { .. }) | None => {}
            }
        }
    }

    /// Reads the next block from the source and parses it.
    fn next_block(&mut self) -> Result<Option<StreamEvent>, StreamError<S::Error>> {
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
            Ok(Some(StreamEvent::Data { len, remaining })) => {
                self.pos = 0;
                self.len = len;
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
pub struct StreamReaderEntry<'a, S> {
    reader: &'a mut TarStreamReader<S>,
}

impl<S> Debug for StreamReaderEntry<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamReaderEntry")
            .field("filename", &self.filename().as_str())
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

impl<S> StreamReaderEntry<'_, S> {
    /// Returns the [`PosixHeader`] of the file.
    #[must_use]
    pub const fn posix_header(&self) -> &PosixHeader {
        PosixHeader::from_block(&self.reader.header, 0)
    }

    /// Filename of the file, including the ustar prefix if there is one.
    #[must_use]
    pub fn filename(&self) -> TarFormatString<POSIX_1003_MAX_FILENAME_LEN> {
        self.posix_header().filename()
    }

    /// Size of the file in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.reader.size
    }
}

impl<S: BlockSource> StreamReaderEntry<'_, S> {
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
