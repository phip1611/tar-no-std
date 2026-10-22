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
        header_block_index: usize,
        remaining: usize,
        skip: bool,
    },
    FirstZeroBlock,
    End,
    Failed(CorruptDataError),
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
/// Once an error was returned, the parser keeps returning the same error.
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
/// parser.finish().unwrap();
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
        let event = self.next_event(block_index, block);
        if let Err(error) = event {
            self.state = State::Failed(error);
        }
        event
    }

    fn next_event<'a>(
        &mut self,
        block_index: usize,
        block: &'a [u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent<'a>>, CorruptDataError> {
        match self.state {
            State::Failed(error) => Err(error),
            State::End => Ok(None),
            State::FirstZeroBlock => {
                if PosixHeader::from_block(block, 0).is_zero_block() {
                    self.state = State::End;
                    Ok(Some(StreamEvent::End))
                } else {
                    Err(CorruptDataError::MissingTerminator)
                }
            }
            State::Payload {
                header_block_index,
                remaining,
                skip,
            } => {
                let len = remaining.min(BLOCKSIZE);
                let remaining = remaining - len;
                self.state = if remaining == 0 {
                    State::Header
                } else {
                    State::Payload {
                        header_block_index,
                        remaining,
                        skip,
                    }
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
                        header_block_index: block_index,
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

    /// Checks that the archive was complete once all blocks were parsed.
    ///
    /// # Errors
    /// Returns [`CorruptDataError`] if no block was parsed, if the payload of
    /// the last entry is incomplete, if the terminator is missing, or if a
    /// previous block was invalid.
    pub const fn finish(&self) -> Result<(), CorruptDataError> {
        match self.state {
            State::End => Ok(()),
            State::Failed(error) => Err(error),
            State::Payload {
                header_block_index, ..
            } => Err(CorruptDataError::PayloadExtendsBeyondArchive {
                block_index: header_block_index,
            }),
            State::Header if self.block_index == 0 => Err(CorruptDataError::EmptyArchive),
            State::Header | State::FirstZeroBlock => Err(CorruptDataError::MissingTerminator),
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

    fn parse(data: &[u8]) -> Result<Vec<ParsedEntry>, CorruptDataError> {
        let mut parser = TarStreamParser::new();
        let mut entries: Vec<ParsedEntry> = Vec::new();
        for block in blocks(data) {
            match parser.parse_block(block)? {
                Some(StreamEvent::Entry(entry)) => {
                    assert!(entry.type_flag().is_regular_file());
                    assert_eq!(
                        entry.posix_header().typeflag.try_to_type_flag(),
                        Ok(entry.type_flag())
                    );
                    entries.push(ParsedEntry {
                        block_index: entry.block_index(),
                        filename: entry.filename().as_str().unwrap().to_string(),
                        data: Vec::with_capacity(entry.payload_size()),
                    });
                }
                Some(StreamEvent::Data { bytes, .. }) => {
                    entries.last_mut().unwrap().data.extend_from_slice(bytes);
                }
                Some(StreamEvent::End) => break,
                None => {}
            }
        }
        parser.finish()?;
        Ok(entries)
    }

    fn parse_files(data: &[u8]) -> Vec<(String, Vec<u8>)> {
        parse(data)
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
        let entries = parse(include_bytes!("../tests/gnu_tar_default_with_dir.tar")).unwrap();
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
        let entries = parse(data).unwrap();
        assert!(entries[0].block_index > 1);
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
        assert_eq!(parser.finish(), Ok(()));
    }

    #[test]
    fn test_empty_archive_is_valid() {
        assert_eq!(parse(&[0; 2 * BLOCKSIZE]), Ok(Vec::new()));
    }

    #[test]
    fn test_rejects_invalid_checksum() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[0] ^= 0xff;
        assert_eq!(
            parse(&data),
            Err(CorruptDataError::InvalidChecksum { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_invalid_type_flag() {
        let mut block = header_block(include_bytes!("../tests/gnu_tar_default.tar"));
        block[156] = b'?';
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block).err(),
            Some(CorruptDataError::InvalidTypeFlag { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_invalid_payload_size() {
        let mut block = header_block(include_bytes!("../tests/gnu_tar_default.tar"));
        block[124] = 0xff;
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block).err(),
            Some(CorruptDataError::InvalidPayloadSize { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_truncated_payload() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut parser = TarStreamParser::new();
        for block in blocks(&data[..2 * BLOCKSIZE]) {
            parser.parse_block(block).unwrap();
        }
        assert_eq!(
            parser.finish(),
            Err(CorruptDataError::PayloadExtendsBeyondArchive { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_truncated_payload_of_skipped_entry() {
        let data = include_bytes!("../tests/gnu_tar_pax.tar");
        let mut parser = TarStreamParser::new();
        assert!(parser.parse_block(&header_block(data)).unwrap().is_none());
        assert_eq!(
            parser.finish(),
            Err(CorruptDataError::PayloadExtendsBeyondArchive { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_missing_terminator() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let end_of_entries = data.len() - 2 * BLOCKSIZE;
        let end_of_entries = data[..end_of_entries]
            .chunks_exact(BLOCKSIZE)
            .rposition(|block| block.iter().any(|&b| b != 0))
            .unwrap()
            + 1;
        assert_eq!(
            parse(&data[..end_of_entries * BLOCKSIZE]),
            Err(CorruptDataError::MissingTerminator)
        );
        assert_eq!(
            parse(&[0; BLOCKSIZE]),
            Err(CorruptDataError::MissingTerminator)
        );
    }

    #[test]
    fn test_rejects_single_zero_block_followed_by_data() {
        let mut data = std::vec![0; BLOCKSIZE];
        data.extend_from_slice(&header_block(include_bytes!(
            "../tests/gnu_tar_default.tar"
        )));
        assert_eq!(parse(&data), Err(CorruptDataError::MissingTerminator));
    }

    #[test]
    fn test_rejects_empty_input() {
        assert_eq!(
            TarStreamParser::new().finish(),
            Err(CorruptDataError::EmptyArchive)
        );
    }

    #[test]
    fn test_errors_are_sticky() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[0] ^= 0xff;
        let mut parser = TarStreamParser::new();
        let error = CorruptDataError::InvalidChecksum { block_index: 0 };
        assert_eq!(parser.parse_block(&header_block(&data)).err(), Some(error));
        assert_eq!(parser.parse_block(&[0; BLOCKSIZE]).err(), Some(error));
        assert_eq!(parser.parse_block(&[0; BLOCKSIZE]).err(), Some(error));
        assert_eq!(parser.finish(), Err(error));
    }

    #[test]
    fn test_stream_rejects_weird_fuzzing_tarballs() {
        let main_tarball =
            TarArchiveRef::new(include_bytes!("../tests/weird_fuzzing_tarballs.tar")).unwrap();
        let mut checked = 0;
        for fuzzing_input in main_tarball.entries() {
            let data = fuzzing_input.data();
            if data.len() % BLOCKSIZE == 0 {
                assert!(parse(data).is_err());
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}
