// SPDX-License-Identifier: MIT

//! Module for [`TarStreamParser`], which parses a Tar archive one block at a
//! time, without requiring the whole archive in memory.

use crate::BLOCKSIZE;
use crate::archive::CorruptDataError;
use crate::header::{PosixHeader, TypeFlag};
use log::warn;

/// Event returned by [`TarStreamParser::parse_block`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// The block is the header of a regular file. If the file has a payload,
    /// the next blocks produce [`StreamEvent::Data`] events.
    Entry {
        /// Size of the file in bytes.
        size: usize,
    },
    /// The block holds payload bytes of the current file.
    Data {
        /// Number of payload bytes at the start of the block. The rest of the
        /// block is padding.
        len: usize,
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
    /// The next block is a header or the first zero block of the terminator.
    #[default]
    Header,
    /// The next block holds payload, of an entry that is skipped if `skip`
    /// is set.
    Payload { remaining: usize, skip: bool },
    /// The next block must be the second zero block of the terminator.
    FirstZeroBlock,
    /// The terminator was read, so the next blocks are ignored.
    End,
}

/// Parses a Tar archive incrementally, one 512-byte block at a time.
///
/// The parser only keeps a few words of state. It validates each header like
/// [`TarArchiveRef::new`] does: checksums, type flags, payload sizes, and the
/// double-zero terminator.
///
/// Like [`ArchiveEntryIterator`], only regular files are reported.
/// Directories, links, PAX extended headers, and other special entries are
/// validated and then skipped together with their payload. Blocks after the
/// terminator are ignored.
///
/// [`TarArchiveRef::new`]: crate::TarArchiveRef::new
/// [`ArchiveEntryIterator`]: crate::ArchiveEntryIterator
#[derive(Debug, Default)]
pub struct TarStreamParser {
    /// What the next block must be.
    state: State,
    /// Index of the next block in the archive.
    block_index: usize,
}

impl TarStreamParser {
    /// Creates a parser positioned at the start of an archive.
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
    pub fn parse_block(
        &mut self,
        block: &[u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent>, CorruptDataError> {
        let block_index = self.block_index;
        self.block_index = self.block_index.saturating_add(1);
        self.next_event(block_index, block)
    }

    /// Parses `block` according to the current state and moves on to the
    /// next state.
    fn next_event(
        &mut self,
        block_index: usize,
        block: &[u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent>, CorruptDataError> {
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
                Ok(Some(StreamEvent::Data { len, remaining }))
            }
            State::Header => {
                let hdr = PosixHeader::from_block(block, 0);
                if hdr.is_zero_block() {
                    self.state = State::FirstZeroBlock;
                    return Ok(None);
                }
                let (type_flag, size) = parse_header(block_index, hdr)?;
                let skip = !type_flag.is_regular_file();
                if size > 0 {
                    self.state = State::Payload {
                        remaining: size,
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
                Ok(Some(StreamEvent::Entry { size }))
            }
        }
    }
}

/// Validates the header at `block_index` and returns its type and payload
/// size.
fn parse_header(
    block_index: usize,
    hdr: &PosixHeader,
) -> Result<(TypeFlag, usize), CorruptDataError> {
    if !hdr.has_valid_checksum() {
        return Err(CorruptDataError::InvalidChecksum { block_index });
    }
    let type_flag = hdr
        .typeflag
        .try_to_type_flag()
        .map_err(|_| CorruptDataError::InvalidTypeFlag { block_index })?;
    let size = if type_flag.has_payload() {
        hdr.size
            .as_number::<usize>()
            .map_err(|_| CorruptDataError::InvalidPayloadSize { block_index })?
    } else {
        0
    };
    Ok((type_flag, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TarArchiveRef;
    use std::string::{String, ToString};
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    struct ParsedEntry {
        block_index: usize,
        filename: String,
        data: Vec<u8>,
    }

    fn blocks(data: &[u8]) -> impl Iterator<Item = &[u8; BLOCKSIZE]> {
        data.chunks_exact(BLOCKSIZE)
            .map(|block| block.try_into().unwrap())
    }

    fn parse_streaming(data: &[u8]) -> Result<Vec<ParsedEntry>, CorruptDataError> {
        let mut parser = TarStreamParser::new();
        let mut entries: Vec<ParsedEntry> = Vec::new();
        for (block_index, block) in blocks(data).enumerate() {
            match parser.parse_block(block)? {
                Some(StreamEvent::Entry { size }) => {
                    let hdr = PosixHeader::from_block(block, 0);
                    assert!(hdr.typeflag.try_to_type_flag().unwrap().is_regular_file());
                    entries.push(ParsedEntry {
                        block_index,
                        filename: hdr.filename().as_str().unwrap().to_string(),
                        data: Vec::with_capacity(size),
                    });
                }
                Some(StreamEvent::Data { len, .. }) => {
                    let data = &mut entries.last_mut().unwrap().data;
                    data.extend_from_slice(&block[..len]);
                }
                Some(StreamEvent::End) => break,
                None => {}
            }
        }
        Ok(entries)
    }

    fn parse_files(data: &[u8]) -> Vec<(String, Vec<u8>)> {
        parse_streaming(data)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.filename, entry.data))
            .collect()
    }

    fn archive_entries(data: &[u8]) -> Vec<(String, Vec<u8>)> {
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

    fn header_block(data: &[u8]) -> [u8; BLOCKSIZE] {
        data[..BLOCKSIZE].try_into().unwrap()
    }

    fn write_checksum(block: &mut [u8; BLOCKSIZE]) {
        block[148..156].fill(b' ');
        let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        block[148..156].copy_from_slice(checksum.as_bytes());
    }

    #[test]
    fn test_stream_matches_archive_entries() {
        for data in [
            include_bytes!("../tests/gnu_tar_default.tar") as &[u8],
            include_bytes!("../tests/gnu_tar_default_with_dir.tar"),
            include_bytes!("../tests/gnu_tar_gnu.tar"),
            include_bytes!("../tests/gnu_tar_oldgnu.tar"),
            include_bytes!("../tests/gnu_tar_pax.tar"),
            include_bytes!("../tests/gnu_tar_posix.tar"),
            include_bytes!("../tests/gnu_tar_ustar.tar"),
            include_bytes!("../tests/gnu_tar_ustar_deep.tar"),
            include_bytes!("../tests/gnu_tar_ustar_long.tar"),
            include_bytes!("../tests/gnu_tar_v7.tar"),
            include_bytes!("../tests/mac_tar_ustar_with_dir.tar"),
            include_bytes!("../tests/weird_fuzzing_tarballs.tar"),
        ] {
            assert_eq!(parse_files(data), archive_entries(data));
        }
    }

    #[test]
    fn test_stream_skips_directories() {
        let entries =
            parse_streaming(include_bytes!("../tests/gnu_tar_default_with_dir.tar")).unwrap();
        let summary = entries
            .iter()
            .map(|entry| (entry.block_index, entry.filename.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                (1, "tests/hello_world.txt"),
                (3, "tests/bye_world_513b.txt"),
                (6, "tests/hello_world_513b.txt"),
            ]
        );
    }

    #[test]
    fn test_stream_skips_pax_headers_with_payload() {
        let data = include_bytes!("../tests/gnu_tar_pax.tar");
        let first_header = PosixHeader::from_block(data, 0);
        assert_eq!(
            first_header.typeflag.try_to_type_flag(),
            Ok(TypeFlag::XHDTYPE)
        );
        let entries = parse_streaming(data).unwrap();
        assert!(entries[0].block_index > 1);
    }

    #[test]
    fn test_data_events_strip_padding() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut parser = TarStreamParser::new();
        let mut blocks = blocks(data);
        let mut next_event = || parser.parse_block(blocks.next().unwrap());

        assert_eq!(next_event(), Ok(Some(StreamEvent::Entry { size: 513 })));
        assert_eq!(
            next_event(),
            Ok(Some(StreamEvent::Data {
                len: 512,
                remaining: 1
            }))
        );
        assert_eq!(
            next_event(),
            Ok(Some(StreamEvent::Data {
                len: 1,
                remaining: 0
            }))
        );
        assert!(matches!(next_event(), Ok(Some(StreamEvent::Entry { .. }))));
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
            .position(|event| *event == Some(StreamEvent::End))
            .unwrap();
        assert!(end < events.len() - 1);
        assert!(events[end + 1..].iter().all(Option::is_none));
    }

    #[test]
    fn test_empty_archive_is_valid() {
        assert_eq!(parse_streaming(&[0; 2 * BLOCKSIZE]), Ok(Vec::new()));
    }

    #[test]
    fn test_rejects_invalid_checksum() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[0] ^= 0xff;
        assert_eq!(
            parse_streaming(&data),
            Err(CorruptDataError::InvalidChecksum { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_invalid_type_flag() {
        let mut block = header_block(include_bytes!("../tests/gnu_tar_default.tar"));
        block[156] = b'?';
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block),
            Err(CorruptDataError::InvalidTypeFlag { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_invalid_payload_size() {
        let mut block = header_block(include_bytes!("../tests/gnu_tar_default.tar"));
        block[124] = 0xff;
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block),
            Err(CorruptDataError::InvalidPayloadSize { block_index: 0 })
        );
    }
}
