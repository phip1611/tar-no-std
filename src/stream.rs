// SPDX-License-Identifier: MIT

//! Module for [`TarStreamParser`], which parses a Tar archive one block at a
//! time.
//!
//! The parser does not require the whole archive in memory. It is also the
//! engine of [`TarStreamReader`].
//!
//! [`TarStreamReader`]: crate::TarStreamReader

use crate::archive::CorruptDataError;
use crate::header::{PosixHeader, TypeFlag};
use crate::pax::PaxScanner;
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, MAX_LONG_NAME_PAYLOAD, POSIX_1003_MAX_FILENAME_LEN};
use log::debug;

/// Event returned by [`TarStreamParser::parse_block`].
///
/// It borrows the block that was passed in.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Boxing needs an allocator, and events are short-lived return values"
)]
pub enum StreamEvent<'a> {
    /// The block is the header of a regular file.
    ///
    /// If the file has a payload, the next blocks produce
    /// [`StreamEvent::Data`] events.
    Entry {
        /// Header of the file.
        posix_header: &'a PosixHeader,
        /// Filename, including the ustar prefix, or the GNU long name or PAX
        /// path if there is one.
        filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
        /// Size of the file in bytes.
        size: usize,
    },
    /// The block holds payload bytes of the current file.
    Data {
        /// Payload bytes of the block, without the padding.
        data: &'a [u8],
        /// Number of payload bytes of the current file in the following
        /// blocks.
        ///
        /// Zero for the last block of the file.
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
    Payload {
        /// Index of the header of the entry.
        header_block_index: usize,
        /// Payload bytes of the entry in the next blocks.
        remaining: usize,
        /// Whether the entry is skipped.
        skip: bool,
    },
    /// The next block holds the payload of a GNU long name entry.
    ///
    /// The payload fits into one block, as it is at most
    /// [`MAX_LONG_NAME_PAYLOAD`] bytes.
    LongName {
        /// Index of the header of the long name.
        header_block_index: usize,
        /// Size of the payload in bytes.
        size: usize,
    },
    /// The next block holds the payload of a PAX extended header.
    Pax {
        /// Index of the PAX extended header.
        header_block_index: usize,
        /// Payload bytes of the header in the next blocks.
        remaining: usize,
        /// Whether the header applies to all following entries (type `g`).
        global: bool,
    },
    /// The next block must be the second zero block of the terminator.
    FirstZeroBlock,
    /// The terminator was read, so the next blocks are ignored.
    End,
    /// A block was invalid, and its error is returned for every next block.
    Failed(CorruptDataError),
}

/// Parses a Tar archive incrementally, one 512-byte block at a time.
///
/// Use it when the blocks are pushed to you, for example by an interrupt, a
/// DMA callback, or the packet handler of a network stack, and you cannot wait
/// for the next block. If you can, [`TarStreamReader`] is simpler: it pulls
/// the blocks itself and takes care of the payload and the end of the archive.
///
/// The parser keeps about 400 bytes of state, most of it for a GNU long name
/// or PAX path. It validates each header like [`TarArchiveRef::new`] does:
/// checksums, type flags, payload sizes, and the double-zero terminator.
///
/// Like [`ArchiveEntryIterator`], only regular files are reported, and GNU
/// long names and PAX paths are applied to their filenames. Directories,
/// links, and other special entries are validated and then skipped together
/// with their payload. Blocks after the terminator are ignored.
///
/// Once an error was returned, the parser keeps returning the same error.
/// Once the input ended, [`TarStreamParser::finish`] checks that the archive
/// was complete.
///
/// # Example
///
/// ```rust
/// use tar_no_std::{CorruptDataError, StreamEvent, TarStreamParser};
///
/// /// Unpacks an archive whose blocks are delivered by a callback.
/// struct Unpacker {
///     parser: TarStreamParser,
///     files: usize,
/// }
///
/// impl Unpacker {
///     /// Called for every 512-byte block of the archive, as it arrives.
///     fn on_block(
///         &mut self,
///         block: &[u8; 512],
///     ) -> Result<(), CorruptDataError> {
///         match self.parser.parse_block(block)? {
///             Some(StreamEvent::Entry { filename, size, .. }) => {
///                 // For example, create the file.
///                 let name = filename.as_str().unwrap_or("?");
///                 println!("{name} ({size} bytes)");
///                 self.files += 1;
///             }
///             Some(StreamEvent::Data { data, remaining }) => {
///                 // For example, write `data` to the file.
///                 println!("  {} bytes, {remaining} left", data.len());
///             }
///             Some(StreamEvent::End) | None => {}
///         }
///         Ok(())
///     }
///
///     /// Called once the input ended.
///     fn on_end(&self) -> Result<(), CorruptDataError> {
///         self.parser.finish()
///     }
/// }
///
/// let mut unpacker = Unpacker {
///     parser: TarStreamParser::new(),
///     files: 0,
/// };
/// // Stands in for the interrupt or network stack that delivers the blocks.
/// let archive = include_bytes!("../tests/gnu_tar_default.tar");
/// for block in archive.chunks_exact(512) {
///     unpacker.on_block(block.try_into().unwrap()).unwrap();
/// }
/// unpacker.on_end().unwrap();
/// assert_eq!(unpacker.files, 3);
/// ```
///
/// [`TarStreamReader`]: crate::TarStreamReader
/// [`TarArchiveRef::new`]: crate::TarArchiveRef::new
/// [`ArchiveEntryIterator`]: crate::ArchiveEntryIterator
#[derive(Debug)]
pub struct TarStreamParser {
    /// What the next block must be.
    state: State,
    /// Index of the next block in the archive.
    block_index: usize,
    /// GNU long name or PAX path of the next entry, if there is one.
    long_name: Option<TarFormatString<POSIX_1003_MAX_FILENAME_LEN>>,
    /// Scanner of the records of the current PAX extended header.
    pax: PaxScanner,
    /// Index of the last PAX extended header and the value of its `size`
    /// record, which must match the size in the next entry header.
    pax_size: Option<(usize, u64)>,
}

impl Default for TarStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TarStreamParser {
    /// Creates a parser positioned at the start of an archive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Header,
            block_index: 0,
            long_name: None,
            pax: PaxScanner::new(false),
            pax_size: None,
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

    /// Parses `block` according to the current state and moves on to the
    /// next state.
    fn next_event<'a>(
        &mut self,
        block_index: usize,
        block: &'a [u8; BLOCKSIZE],
    ) -> Result<Option<StreamEvent<'a>>, CorruptDataError> {
        match self.state {
            State::Failed(error) => Err(error),
            State::End => Ok(None),
            State::LongName {
                header_block_index,
                size,
            } => {
                let name = TarFormatString::from_null_terminated(&block[..size]).ok_or(
                    CorruptDataError::FilenameTooLong {
                        block_index: header_block_index,
                    },
                )?;
                self.long_name = Some(name);
                self.state = State::Header;
                Ok(None)
            }
            State::Pax {
                header_block_index,
                remaining,
                global,
            } => {
                let len = remaining.min(BLOCKSIZE);
                self.pax
                    .feed(&block[..len], &mut self.long_name)
                    .map_err(|error| error.into_corrupt_data_error(header_block_index))?;
                let remaining = remaining - len;
                if remaining > 0 {
                    self.state = State::Pax {
                        header_block_index,
                        remaining,
                        global,
                    };
                } else {
                    self.state = State::Header;
                    if !global {
                        self.pax_size = self.pax.size().map(|size| (header_block_index, size));
                    }
                }
                Ok(None)
            }
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
                    data: &block[..len],
                    remaining,
                }))
            }
            State::Header => {
                let hdr = PosixHeader::from_block(block, 0);
                if hdr.is_zero_block() {
                    self.state = State::FirstZeroBlock;
                    return Ok(None);
                }
                let (typeflag, size) = parse_header(block_index, hdr)?;
                if typeflag == TypeFlag::GNULONGNAME {
                    if size > MAX_LONG_NAME_PAYLOAD {
                        return Err(CorruptDataError::FilenameTooLong { block_index });
                    }
                    if size == 0 {
                        self.long_name = TarFormatString::from_null_terminated(&[]);
                    } else {
                        self.state = State::LongName {
                            header_block_index: block_index,
                            size,
                        };
                    }
                    return Ok(None);
                }
                if !typeflag.is_extension_header() {
                    if let Some((pax_block_index, pax_size)) = self.pax_size.take() {
                        if u64::try_from(size) != Ok(pax_size) {
                            return Err(CorruptDataError::UnsupportedPaxRecord {
                                block_index: pax_block_index,
                            });
                        }
                    }
                }
                if matches!(typeflag, TypeFlag::XHDTYPE | TypeFlag::XGLTYPE) {
                    let global = typeflag == TypeFlag::XGLTYPE;
                    self.pax = PaxScanner::new(global);
                    if size > 0 {
                        self.state = State::Pax {
                            header_block_index: block_index,
                            remaining: size,
                            global,
                        };
                    } else if !global {
                        self.pax_size = None;
                    }
                    return Ok(None);
                }
                let filename = self.long_name.unwrap_or_else(|| hdr.filename());
                let skip = !hdr.is_regular_file(&filename);
                if size > 0 {
                    self.state = State::Payload {
                        header_block_index: block_index,
                        remaining: size,
                        skip,
                    };
                }
                if skip {
                    // Links are skipped, so their long names are not needed,
                    // but the long name of the entry after them is.
                    if typeflag != TypeFlag::GNULONGLINK {
                        debug!("Skipping non-regular entry of type {:?}", hdr.typeflag);
                        self.long_name = None;
                    }
                    return Ok(None);
                }
                self.long_name = None;
                Ok(Some(StreamEvent::Entry {
                    posix_header: hdr,
                    filename,
                    size,
                }))
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
            }
            | State::LongName {
                header_block_index, ..
            }
            | State::Pax {
                header_block_index, ..
            } => Err(CorruptDataError::PayloadExtendsBeyondArchive {
                block_index: header_block_index,
            }),
            State::Header if self.block_index == 0 => Err(CorruptDataError::EmptyArchive),
            State::Header | State::FirstZeroBlock => Err(CorruptDataError::MissingTerminator),
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
    if !type_flag.is_supported() {
        return Err(CorruptDataError::UnsupportedTypeFlag { block_index });
    }
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
    use crate::{TYPEFLAG_OFFSET, TarArchiveRef};
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
                Some(StreamEvent::Entry {
                    posix_header,
                    filename,
                    size,
                }) => {
                    assert!(
                        posix_header
                            .typeflag
                            .try_to_type_flag()
                            .unwrap()
                            .is_regular_file()
                    );
                    entries.push(ParsedEntry {
                        block_index,
                        filename: filename.as_str().unwrap().to_string(),
                        data: Vec::with_capacity(size),
                    });
                }
                Some(StreamEvent::Data { data, .. }) => {
                    entries.last_mut().unwrap().data.extend_from_slice(data);
                }
                Some(StreamEvent::End) => break,
                None => {}
            }
        }
        parser.finish()?;
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
            include_bytes!("../tests/gnu_tar_gnu_long_names.tar"),
            include_bytes!("../tests/gnu_tar_gnu_label.tar"),
            include_bytes!("../tests/gnu_tar_posix_long_names.tar"),
            include_bytes!("../tests/mac_tar_ustar_with_dir.tar"),
            include_bytes!("../tests/weird_fuzzing_tarballs.tar"),
        ] {
            assert_eq!(parse_files(data), archive_entries(data));
        }
    }

    #[test]
    fn test_stream_reports_contiguous_file() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        let mut block = header_block(&data);
        block[TYPEFLAG_OFFSET] = TypeFlag::CONTTYPE.to_byte();
        write_checksum(&mut block);
        data[..BLOCKSIZE].copy_from_slice(&block);

        let files = parse_files(&data);
        assert_eq!(files[0].0, "bye_world_513b.txt");
        assert_eq!(files, archive_entries(&data));
    }

    #[test]
    fn test_stream_skips_old_style_directories() {
        let mut data = include_bytes!("../tests/gnu_tar_default_with_dir.tar").to_vec();
        let mut block = header_block(&data);
        // Turn the directory "tests/" into a regular file of an old archive,
        // which marks a directory by its trailing slash.
        block[TYPEFLAG_OFFSET] = TypeFlag::AREGTYPE.to_byte();
        write_checksum(&mut block);
        data[..BLOCKSIZE].copy_from_slice(&block);

        let files = parse_files(&data);
        assert_eq!(files[0].0, "tests/hello_world.txt");
        assert_eq!(files, archive_entries(&data));
    }

    #[test]
    fn test_stream_rejects_too_long_gnu_long_name() {
        assert_eq!(
            parse_streaming(include_bytes!("../tests/gnu_tar_gnu_too_long_name.tar")),
            Err(CorruptDataError::FilenameTooLong { block_index: 7 })
        );
    }

    #[test]
    fn test_stream_skips_vendor_entries() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        let mut block = header_block(&data);
        // Vendor-specific entry.
        block[TYPEFLAG_OFFSET] = b'I';
        write_checksum(&mut block);
        data[..BLOCKSIZE].copy_from_slice(&block);

        let files = parse_files(&data);
        assert_eq!(files[0].0, "hello_world_513b.txt");
        assert_eq!(files, archive_entries(&data));
    }

    #[test]
    fn test_stream_rejects_unsupported_pax_archives() {
        for (data, error) in [
            (
                &include_bytes!("../tests/gnu_tar_posix_too_long_name.tar")[..],
                CorruptDataError::FilenameTooLong { block_index: 7 },
            ),
            (
                include_bytes!("../tests/gnu_tar_posix_sparse.tar"),
                CorruptDataError::UnsupportedPaxRecord { block_index: 0 },
            ),
        ] {
            assert_eq!(parse_streaming(data), Err(error));
            assert_eq!(TarArchiveRef::new(data), Err(error));
        }
    }

    #[test]
    fn test_stream_checks_pax_size() {
        // Setup: replace the records of the first PAX extended header, which
        // describes a file of 513 bytes.
        let mut data = include_bytes!("../tests/gnu_tar_pax.tar").to_vec();
        for (records, result) in [
            (&b"12 size=513\n"[..], Ok(())),
            (
                b"12 size=999\n",
                Err(CorruptDataError::UnsupportedPaxRecord { block_index: 0 }),
            ),
        ] {
            let mut block = header_block(&data);
            let size = format!("{:011o}\0", records.len());
            block[124..136].copy_from_slice(size.as_bytes());
            write_checksum(&mut block);
            data[..BLOCKSIZE].copy_from_slice(&block);
            data[BLOCKSIZE..2 * BLOCKSIZE].fill(0);
            data[BLOCKSIZE..BLOCKSIZE + records.len()].copy_from_slice(records);

            assert_eq!(parse_streaming(&data).map(|_| ()), result);
            assert_eq!(TarArchiveRef::new(&data).map(|_| ()), result);
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
    fn test_events_borrow_the_block() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");
        let mut parser = TarStreamParser::new();
        let mut blocks = blocks(data);

        let block = blocks.next().unwrap();
        assert_eq!(
            parser.parse_block(block),
            Ok(Some(StreamEvent::Entry {
                posix_header: PosixHeader::from_block(block, 0),
                filename: PosixHeader::from_block(block, 0).filename(),
                size: 513
            }))
        );
        let block = blocks.next().unwrap();
        assert_eq!(
            parser.parse_block(block),
            Ok(Some(StreamEvent::Data {
                data: &block[..],
                remaining: 1
            }))
        );
        // The padding of the last block is cut off.
        let block = blocks.next().unwrap();
        assert_eq!(
            parser.parse_block(block),
            Ok(Some(StreamEvent::Data {
                data: &block[..1],
                remaining: 0
            }))
        );
        let block = blocks.next().unwrap();
        assert!(matches!(
            parser.parse_block(block),
            Ok(Some(StreamEvent::Entry { filename, size: 513, .. }))
                if filename.as_str() == Ok("hello_world_513b.txt")
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
            .position(|event| *event == Some(StreamEvent::End))
            .unwrap();
        assert!(end < events.len() - 1);
        assert!(events[end + 1..].iter().all(Option::is_none));
        assert_eq!(parser.finish(), Ok(()));
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
        // Unknown type flag.
        block[TYPEFLAG_OFFSET] = b'?';
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block),
            Err(CorruptDataError::InvalidTypeFlag { block_index: 0 })
        );
    }

    #[test]
    fn test_rejects_unsupported_type_flag() {
        let mut block = header_block(include_bytes!("../tests/gnu_tar_default.tar"));
        block[TYPEFLAG_OFFSET] = TypeFlag::GNUSPARSE.to_byte();
        write_checksum(&mut block);
        assert_eq!(
            TarStreamParser::new().parse_block(&block),
            Err(CorruptDataError::UnsupportedTypeFlag { block_index: 0 })
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
        assert_eq!(parser.parse_block(&header_block(data)), Ok(None));
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
            parse_streaming(&data[..end_of_entries * BLOCKSIZE]),
            Err(CorruptDataError::MissingTerminator)
        );
        assert_eq!(
            parse_streaming(&[0; BLOCKSIZE]),
            Err(CorruptDataError::MissingTerminator)
        );
    }

    #[test]
    fn test_rejects_single_zero_block_followed_by_data() {
        let mut data = std::vec![0; BLOCKSIZE];
        data.extend_from_slice(&header_block(include_bytes!(
            "../tests/gnu_tar_default.tar"
        )));
        assert_eq!(
            parse_streaming(&data),
            Err(CorruptDataError::MissingTerminator)
        );
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
        assert_eq!(parser.parse_block(&header_block(&data)), Err(error));
        assert_eq!(parser.parse_block(&[0; BLOCKSIZE]), Err(error));
        assert_eq!(parser.parse_block(&[0; BLOCKSIZE]), Err(error));
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
                assert!(parse_streaming(data).is_err());
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}
