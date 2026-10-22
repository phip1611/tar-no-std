// SPDX-License-Identifier: MIT

//! Module for [`TarStreamParser`], which parses a Tar archive one block at a
//! time, without requiring the whole archive in memory.

use crate::archive::CorruptDataError;
use crate::header::{PosixHeader, TypeFlag};
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, POSIX_1003_MAX_FILENAME_LEN};
use log::warn;

/// Header of a regular file in the archive, as reported by
/// [`TarStreamParser`].
#[derive(Debug)]
pub struct StreamEntry<'a> {
    block_index: usize,
    posix_header: &'a PosixHeader,
    type_flag: TypeFlag,
    payload_size: usize,
}

impl<'a> StreamEntry<'a> {
    /// Index of the header block in the archive.
    #[must_use]
    pub const fn block_index(&self) -> usize {
        self.block_index
    }

    /// Returns the [`PosixHeader`] of the entry.
    #[must_use]
    pub const fn posix_header(&self) -> &'a PosixHeader {
        self.posix_header
    }

    /// Type of the entry.
    #[must_use]
    pub const fn type_flag(&self) -> TypeFlag {
        self.type_flag
    }

    /// Filename of the entry, including the ustar prefix if there is one.
    #[must_use]
    pub fn filename(&self) -> TarFormatString<POSIX_1003_MAX_FILENAME_LEN> {
        self.posix_header.filename()
    }

    /// Number of payload bytes that follow the header.
    #[must_use]
    pub const fn payload_size(&self) -> usize {
        self.payload_size
    }
}

/// Event returned by [`TarStreamParser::parse_block`].
#[derive(Debug)]
pub enum StreamEvent<'a> {
    /// The block is the header of a regular file. If the file has a payload,
    /// the next blocks produce [`StreamEvent::Data`] events.
    Entry(StreamEntry<'a>),
    /// The block holds payload bytes of the current file.
    Data {
        /// Payload bytes in this block, without the padding of the last block.
        bytes: &'a [u8],
        /// Number of payload bytes of the current file in the following
        /// blocks. Zero for the last block of the file.
        remaining: usize,
    },
    /// The block is the second zero block that terminates the archive.
    End,
}

/// Position of the parser in the archive, i.e. what the next block must be.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Header,
    Payload {
        remaining: usize,
        skip: bool,
    },
    FirstZeroBlock,
    End,
}

/// Parses a Tar archive incrementally, one 512-byte block at a time.
///
/// The parser only keeps a few words of state, so archives can be read from
/// a file, a flash device, or a network stream without loading them into
/// memory. It validates each header like [`TarArchiveRef::new`] does:
/// checksums, type flags, payload sizes, and the double-zero terminator.
///
/// Like [`ArchiveEntryIterator`], only regular files are reported.
/// Directories, links, PAX extended headers, and other special entries are
/// validated and then skipped together with their payload. Files with a
/// payload are followed by [`StreamEvent::Data`] events. Blocks after the
/// terminator are ignored.
///
/// # Example
///
/// ```rust
/// use tar_no_std::{StreamEvent, TarStreamParser};
///
/// let archive = include_bytes!("../tests/gnu_tar_default.tar");
/// let mut parser = TarStreamParser::new();
/// for block in archive.chunks_exact(512) {
///     match parser.parse_block(block.try_into().unwrap()).unwrap() {
///         Some(StreamEvent::Entry(entry)) => {
///             println!("{:?} ({} bytes)", entry.filename(), entry.payload_size());
///         }
///         Some(StreamEvent::Data { bytes, .. }) => {
///             println!("  {} bytes of data", bytes.len());
///         }
///         Some(StreamEvent::End) => break,
///         None => {}
///     }
/// }
/// ```
///
/// [`TarArchiveRef::new`]: crate::TarArchiveRef::new
/// [`ArchiveEntryIterator`]: crate::ArchiveEntryIterator
#[derive(Debug, Default)]
pub struct TarStreamParser {
    state: State,
    block_index: usize,
}

impl TarStreamParser {
    /// Creates a parser positioned at the start of an archive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Header,
            block_index: 0,
        }
    }

    /// Parses the next block of the archive.
    ///
    /// Returns `None` for blocks that do not produce an event: headers and
    /// payload of skipped entries, the first of the two terminating zero
    /// blocks, and any block after the terminator.
    ///
    /// # Errors
    /// Returns [`CorruptDataError`] if the block is invalid.
    pub fn parse_block<'a>(
        &mut self,
        block: &'a [u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent<'a>>, CorruptDataError> {
        let block_index = self.block_index;
        self.block_index = self.block_index.saturating_add(1);
        self.next_event(block_index, block)
    }

    fn next_event<'a>(
        &mut self,
        block_index: usize,
        block: &'a [u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent<'a>>, CorruptDataError> {
        match self.state {
            State::End => Ok(None),
            State::FirstZeroBlock => {
                if PosixHeader::from_block(block, 0).is_zero_block() {
                    self.state = State::End;
                    Ok(Some(StreamEvent::End))
                } else {
                    Err(CorruptDataError::MissingTerminator)
                }
            }
            State::Payload { remaining, skip } => {
                let len = remaining.min(BLOCKSIZE);
                let remaining = remaining - len;
                self.state = if remaining == 0 {
                    State::Header
                } else {
                    State::Payload { remaining, skip }
                };
                if skip {
                    return Ok(None);
                }
                Ok(Some(StreamEvent::Data {
                    bytes: &block[..len],
                    remaining,
                }))
            }
            State::Header => {
                let hdr = PosixHeader::from_block(block, 0);
                if hdr.is_zero_block() {
                    self.state = State::FirstZeroBlock;
                    return Ok(None);
                }
                let entry = parse_header(block_index, hdr)?;
                let skip = !entry.type_flag.is_regular_file();
                if entry.payload_size > 0 {
                    self.state = State::Payload {
                        remaining: entry.payload_size,
                        skip,
                    };
                }
                if skip {
                    warn!(
                        "Skipping entry of type {:?} (not supported yet)",
                        hdr.typeflag
                    );
                    return Ok(None);
                }
                Ok(Some(StreamEvent::Entry(entry)))
            }
        }
    }
}

fn parse_header(
    block_index: usize,
    hdr: &PosixHeader,
) -> Result<StreamEntry<'_>, CorruptDataError> {
    if !hdr.has_valid_checksum() {
        return Err(CorruptDataError::InvalidChecksum { block_index });
    }
    let type_flag = hdr
        .typeflag
        .try_to_type_flag()
        .map_err(|_| CorruptDataError::InvalidTypeFlag { block_index })?;
    let payload_size = if type_flag.has_payload() {
        hdr.size
            .as_number::<usize>()
            .map_err(|_| CorruptDataError::InvalidPayloadSize { block_index })?
    } else {
        0
    };
    Ok(StreamEntry {
        block_index,
        posix_header: hdr,
        type_flag,
        payload_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn blocks(data: &[u8]) -> impl Iterator<Item = &[u8; BLOCKSIZE]> {
        data.chunks_exact(BLOCKSIZE)
            .map(|block| block.try_into().unwrap())
    }

    #[test]
    fn test_data_events_strip_padding() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut parser = TarStreamParser::new();
        let mut blocks = blocks(data);

        let Some(StreamEvent::Entry(entry)) = parser.parse_block(blocks.next().unwrap()).unwrap()
        else {
            panic!("first block should be a header");
        };
        assert_eq!(entry.payload_size(), 513);

        let Some(StreamEvent::Data { bytes, remaining }) =
            parser.parse_block(blocks.next().unwrap()).unwrap()
        else {
            panic!("second block should be data");
        };
        assert_eq!((bytes.len(), remaining), (512, 1));

        let Some(StreamEvent::Data { bytes, remaining }) =
            parser.parse_block(blocks.next().unwrap()).unwrap()
        else {
            panic!("third block should be data");
        };
        assert_eq!((bytes.len(), remaining), (1, 0));

        assert!(matches!(
            parser.parse_block(blocks.next().unwrap()),
            Ok(Some(StreamEvent::Entry(_)))
        ));
    }

    #[test]
    fn test_blocks_after_end_are_ignored() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data.extend_from_slice(&[0xff; BLOCKSIZE]);
        let mut parser = TarStreamParser::new();
        let mut events = Vec::new();
        for block in blocks(&data) {
            events.push(parser.parse_block(block).unwrap());
        }
        let end = events
            .iter()
            .position(|event| matches!(event, Some(StreamEvent::End)))
            .unwrap();
        assert!(end < events.len() - 1);
        assert!(events[end + 1..].iter().all(Option::is_none));
    }
}
