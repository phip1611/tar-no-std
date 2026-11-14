// SPDX-License-Identifier: MIT

//! Module for [`TarArchiveRef`], which reads a Tar archive in memory.
//!
//! If the `alloc`-feature is enabled, this crate also exports `TarArchive`,
//! which owns data on the heap.

use crate::header::{PosixHeader, TypeFlag};
use crate::pax::PaxScanner;
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, MAX_LONG_NAME_PAYLOAD, POSIX_1003_MAX_FILENAME_LEN};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter};
use core::str::Utf8Error;
use core::{error, fmt};
use log::debug;

/// Regular file in a [`TarArchiveRef`] or `TarArchive`.
///
/// Directories and other special entries are not supported.
pub struct ArchiveEntry<'a> {
    /// Filename, including the ustar prefix.
    filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
    /// Payload of the file, without padding.
    data: &'a [u8],
    /// Size of the payload in bytes.
    size: usize,
    /// Header of the file in the archive.
    posix_header: &'a PosixHeader,
}

impl<'a> ArchiveEntry<'a> {
    /// Creates an entry from its parts.
    const fn new(
        filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
        data: &'a [u8],
        posix_header: &'a PosixHeader,
    ) -> Self {
        ArchiveEntry {
            filename,
            data,
            size: data.len(),
            posix_header,
        }
    }

    /// Filename of the entry, including the ustar prefix, or the GNU long name
    /// or PAX path if there is one.
    #[must_use]
    pub const fn filename(&self) -> TarFormatString<{ POSIX_1003_MAX_FILENAME_LEN }> {
        self.filename
    }

    /// Data of the file.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Data of the file as string slice, if data is valid UTF-8.
    ///
    /// # Errors
    /// Returns a [`Utf8Error`] error for invalid strings.
    #[allow(clippy::missing_const_for_fn, reason = "MSRV compliance")]
    pub fn data_as_str(&self) -> Result<&'a str, Utf8Error> {
        use core::str;
        str::from_utf8(self.data)
    }

    /// Filesize in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the [`PosixHeader`] for the entry.
    #[must_use]
    pub const fn posix_header(&self) -> &'a PosixHeader {
        self.posix_header
    }
}

impl Debug for ArchiveEntry<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveEntry")
            .field("filename", &self.filename().as_str())
            .field("size", &self.size())
            .field("data", &"<bytes>")
            .finish()
    }
}

/// Describes why archive validation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CorruptDataError {
    /// The archive contains no data.
    EmptyArchive,
    /// The archive length is not a multiple of the 512-byte block size.
    InvalidBlockSize,
    /// The header at `block_index` has an invalid checksum.
    InvalidChecksum {
        /// Index of the invalid header block.
        block_index: usize,
    },
    /// The header at `block_index` has an unsupported type flag.
    InvalidTypeFlag {
        /// Index of the invalid header block.
        block_index: usize,
    },
    /// The payload size in the header at `block_index` is invalid.
    InvalidPayloadSize {
        /// Index of the header with the invalid payload size.
        block_index: usize,
    },
    /// The payload described by the header at `block_index` extends past the
    /// archive.
    PayloadExtendsBeyondArchive {
        /// Index of the header that describes the payload.
        block_index: usize,
    },
    /// The archive does not end with two zero blocks.
    MissingTerminator,
    /// The GNU long name or PAX path at `block_index` is longer than 256
    /// bytes.
    ///
    /// The formats have no limit, but this crate does not support longer
    /// names, as it stores them without allocating.
    FilenameTooLong {
        /// Index of the header of the long name or PAX path.
        block_index: usize,
    },
}

impl Display for CorruptDataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyArchive => f.write_str("archive contains no data"),
            Self::InvalidBlockSize => f.write_str("archive length is not a multiple of 512 bytes"),
            Self::InvalidChecksum { block_index } => {
                write!(f, "header at block {block_index} has an invalid checksum")
            }
            Self::InvalidTypeFlag { block_index } => {
                write!(f, "header at block {block_index} has an invalid type flag")
            }
            Self::InvalidPayloadSize { block_index } => {
                write!(
                    f,
                    "header at block {block_index} has an invalid payload size"
                )
            }
            Self::PayloadExtendsBeyondArchive { block_index } => write!(
                f,
                "payload described by header at block {block_index} extends beyond the archive"
            ),
            Self::MissingTerminator => f.write_str("archive does not end with two zero blocks"),
            Self::FilenameTooLong { block_index } => write!(
                f,
                "filename at block {block_index} is longer than {POSIX_1003_MAX_FILENAME_LEN} bytes"
            ),
        }
    }
}

impl error::Error for CorruptDataError {}

/// An owning, validated Tar archive.
///
/// Unlike [`TarArchiveRef`], this type takes ownership of the archive bytes.
/// [`TarArchive::new`] validates the supplied data before constructing the
/// archive.
///
/// This is only available with the `alloc` feature of this crate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchive {
    /// Validated archive bytes.
    data: Box<[u8]>,
}

#[cfg(feature = "alloc")]
impl TarArchive {
    /// Creates an owning wrapper around validated Tar archive bytes.
    ///
    /// The supplied data must have a valid block layout and end with two zero
    /// blocks. Each archive header must have a valid checksum and type flag,
    /// and every payload size must lead to a header or the terminating zero
    /// blocks within the archive.
    ///
    /// Validation checks the archive structure required for safe iteration. It
    /// does not guarantee that every supported entry can be consumed without
    /// further format-specific limitations; see [`ArchiveEntryIterator`].
    ///
    /// Returns an error, if the sanity checks report problems.
    ///
    /// # Errors
    /// Returns [`CorruptDataError`] if validation fails.
    pub fn new(data: Box<[u8]>) -> Result<Self, CorruptDataError> {
        TarArchiveRef::validate(&data).map(|_| Self { data })
    }

    /// Iterates over the regular files in the Tar archive.
    ///
    /// See [`ArchiveEntryIterator`] for format support and limitations.
    #[must_use]
    pub fn entries(&self) -> ArchiveEntryIterator<'_> {
        ArchiveEntryIterator::new(self.data.as_ref())
    }

    /// Iterates over the headers in the Tar archive.
    ///
    /// PAX extended headers are returned as normal [`PosixHeader`] values,
    /// while their payload blocks are skipped before the next iteration.
    #[must_use]
    pub fn headers(&self) -> ArchiveHeaderIterator<'_> {
        ArchiveHeaderIterator::new(self.data.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Box<[u8]>> for TarArchive {
    type Error = CorruptDataError;

    fn try_from(data: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::new(data)
    }
}

#[cfg(feature = "alloc")]
impl From<TarArchive> for Box<[u8]> {
    fn from(ar: TarArchive) -> Self {
        ar.data
    }
}

/// Validated Tar archive that borrows its bytes.
///
/// To iterate the entries, use [`TarArchiveRef::entries`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchiveRef<'a> {
    /// Validated archive bytes.
    data: &'a [u8],
}

impl<'a> TarArchiveRef<'a> {
    /// Creates a borrowed wrapper around validated Tar archive bytes.
    ///
    /// The supplied data must have a valid block layout and end with two zero
    /// blocks. Each archive header must have a valid checksum and type flag,
    /// and every payload size must lead to a header or the terminating zero
    /// blocks within the archive.
    ///
    /// Validation checks the archive structure required for safe iteration. It
    /// does not guarantee that every supported entry can be consumed without
    /// further format-specific limitations; see [`ArchiveEntryIterator`].
    ///
    /// # Errors
    /// Returns [`CorruptDataError`] if validation fails.
    pub fn new(data: &'a [u8]) -> Result<Self, CorruptDataError> {
        Self::validate(data).map(|()| Self { data })
    }

    /// Validates the archive's overall block layout and header sequence.
    ///
    /// The archive must not be empty and must have a length that is a multiple
    /// of [`BLOCKSIZE`].
    /// Header-specific validation is delegated to [`Self::validate_headers`].
    fn validate(data: &'a [u8]) -> Result<(), CorruptDataError> {
        if data.is_empty() {
            return Err(CorruptDataError::EmptyArchive);
        }
        if data.len() % BLOCKSIZE != 0 {
            return Err(CorruptDataError::InvalidBlockSize);
        }

        Self::validate_headers(data)
    }

    /// Validates the archive's header sequence and terminator.
    ///
    /// Rejects invalid checksums, type flags, and payload sizes, as well as a
    /// missing double-zero terminator.
    /*
     * Do not use ArchiveHeaderIterator's Iterator implementation here. It
     * assumes validated data, whereas validation must reject malformed headers
     * and only accept an explicit double-zero terminator.
     */
    fn validate_headers(data: &'a [u8]) -> Result<(), CorruptDataError> {
        let header_iter = ArchiveHeaderIterator::new(data);
        let total_block_count = data.len() / BLOCKSIZE;
        let mut block_index = 0;

        loop {
            if block_index >= total_block_count {
                return Err(CorruptDataError::MissingTerminator);
            }

            let hdr = header_iter.block_as_header(block_index);
            if hdr.is_zero_block() {
                return (block_index + 1 < total_block_count
                    && header_iter.block_as_header(block_index + 1).is_zero_block())
                .then_some(())
                .ok_or(CorruptDataError::MissingTerminator);
            }

            if !hdr.has_valid_checksum() {
                return Err(CorruptDataError::InvalidChecksum { block_index });
            }

            let typeflag = hdr
                .typeflag
                .try_to_type_flag()
                .map_err(|_| CorruptDataError::InvalidTypeFlag { block_index })?;
            let mut next_block_index = block_index
                .checked_add(1)
                .ok_or(CorruptDataError::PayloadExtendsBeyondArchive { block_index })?;
            let mut size = 0;
            if typeflag.has_payload() {
                size = hdr
                    .size
                    .as_number::<usize>()
                    .map_err(|_| CorruptDataError::InvalidPayloadSize { block_index })?;
                next_block_index = next_block_index
                    .checked_add(size.div_ceil(BLOCKSIZE))
                    .ok_or(CorruptDataError::PayloadExtendsBeyondArchive { block_index })?;
            }
            // Checked before the payload, like TarStreamParser does.
            let is_long_name = typeflag == TypeFlag::GNULONGNAME;
            if is_long_name && size > MAX_LONG_NAME_PAYLOAD {
                return Err(CorruptDataError::FilenameTooLong { block_index });
            }
            // TarStreamParser reports errors in the records before it knows
            // that the payload is incomplete, so scan what is there first.
            if typeflag == TypeFlag::XHDTYPE {
                let start = (block_index + 1) * BLOCKSIZE;
                let end = start.saturating_add(size).min(data.len());
                PaxScanner::new()
                    .feed(&data[start..end], &mut None)
                    .map_err(|error| error.into_corrupt_data_error(block_index))?;
            }
            if next_block_index > total_block_count {
                return Err(CorruptDataError::PayloadExtendsBeyondArchive { block_index });
            }
            if is_long_name {
                let payload = &data[(block_index + 1) * BLOCKSIZE..][..size];
                if TarFormatString::<POSIX_1003_MAX_FILENAME_LEN>::from_null_terminated(payload)
                    .is_none()
                {
                    return Err(CorruptDataError::FilenameTooLong { block_index });
                }
            }
            block_index = next_block_index;
        }
    }

    /// Iterates over the regular files in the Tar archive.
    ///
    /// See [`ArchiveEntryIterator`] for format support and limitations.
    #[must_use]
    pub fn entries(&self) -> ArchiveEntryIterator<'a> {
        ArchiveEntryIterator::new(self.data)
    }

    /// Iterates over the headers in the Tar archive.
    ///
    /// PAX extended headers are returned as normal [`PosixHeader`] values,
    /// while their payload blocks are skipped before the next iteration.
    #[must_use]
    pub fn headers(&self) -> ArchiveHeaderIterator<'a> {
        ArchiveHeaderIterator::new(self.data)
    }
}

/// Iterates over the headers of a validated Tar archive.
///
/// PAX extended headers are returned as normal [`PosixHeader`] values, while
/// their payload blocks are skipped before the next iteration. Obtain this
/// iterator with
#[cfg_attr(feature = "alloc", doc = " [`TarArchive::headers`] or")]
/// [`TarArchiveRef::headers`].
#[derive(Debug)]
pub struct ArchiveHeaderIterator<'a> {
    /// Validated archive bytes.
    archive_data: &'a [u8],
    /// Index of the block with the next header.
    next_hdr_block_index: usize,
}

impl<'a> ArchiveHeaderIterator<'a> {
    /// Creates an iterator over the headers of validated archive bytes.
    #[must_use]
    fn new(archive: &'a [u8]) -> Self {
        assert!(!archive.is_empty());
        assert_eq!(archive.len() % BLOCKSIZE, 0);
        Self {
            archive_data: archive,
            next_hdr_block_index: 0,
        }
    }

    /// Parse the memory at the given block as [`PosixHeader`].
    const fn block_as_header(&self, block_index: usize) -> &'a PosixHeader {
        PosixHeader::from_block(self.archive_data, block_index)
    }
}

/// Index of a 512-byte block in the archive.
type BlockIndex = usize;

impl<'a> Iterator for ArchiveHeaderIterator<'a> {
    type Item = (BlockIndex, &'a PosixHeader);

    /// Returns the next header and advances past its payload blocks.
    fn next(&mut self) -> Option<Self::Item> {
        let total_block_count = self.archive_data.len() / BLOCKSIZE;
        if self.next_hdr_block_index >= total_block_count {
            return None;
        }

        let hdr = self.block_as_header(self.next_hdr_block_index);
        let block_index = self.next_hdr_block_index;

        // Validation guarantees a double-zero terminator. The first zero block
        // marks the end of the archive.
        if hdr.is_zero_block() {
            return None;
        }

        // Start at next block on next iteration.
        self.next_hdr_block_index += 1;

        // We only update the block index for types that have a payload.
        // In directory entries, for example, the size field has other
        // semantics. See spec.
        let typeflag = hdr
            .typeflag
            .try_to_type_flag()
            .expect("type flag should be valid after successful validation");
        if typeflag.has_payload() {
            let payload_block_count = hdr
                .payload_block_count()
                .expect("payload size should be valid after successful validation");
            self.next_hdr_block_index += payload_block_count;
        }

        Some((block_index, hdr))
    }
}

/// Iterator over the files of the archive.
///
/// Only regular files are yielded. Directories, links, and other special
/// entries ([`crate::TypeFlag`]) are skipped.
///
/// GNU long names and PAX paths are applied to the filename of the following
/// file. Other PAX records, such as high-precision timestamps, are skipped.
/// Directory paths encoded in the names are preserved.
#[derive(Debug)]
pub struct ArchiveEntryIterator<'a>(ArchiveHeaderIterator<'a>);

impl<'a> ArchiveEntryIterator<'a> {
    /// Creates an iterator over the regular files of validated archive bytes.
    fn new(archive: &'a [u8]) -> Self {
        Self(ArchiveHeaderIterator::new(archive))
    }

    /// Returns the next header of any type.
    fn next_hdr(&mut self) -> Option<(BlockIndex, &'a PosixHeader)> {
        self.0.next()
    }

    /// Returns the payload of the header at `block_index`.
    fn payload(&self, block_index: BlockIndex, hdr: &PosixHeader) -> &'a [u8] {
        let size = hdr
            .size
            .as_number::<usize>()
            .expect("payload size should be valid after successful validation");
        &self.0.archive_data[(block_index + 1) * BLOCKSIZE..][..size]
    }
}

impl<'a> Iterator for ArchiveEntryIterator<'a> {
    type Item = ArchiveEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // GNU long name or PAX path of the next entry, if there is one.
        let mut long_name = None;
        loop {
            let (block_index, hdr) = self.next_hdr()?;
            let typeflag = hdr
                .typeflag
                .try_to_type_flag()
                .expect("type flag should be valid after successful validation");
            if typeflag == TypeFlag::GNULONGNAME {
                let name = TarFormatString::from_null_terminated(self.payload(block_index, hdr))
                    .expect("long name should be valid after successful validation");
                long_name = Some(name);
                continue;
            }
            if typeflag == TypeFlag::XHDTYPE {
                PaxScanner::new()
                    .feed(self.payload(block_index, hdr), &mut long_name)
                    .expect("PAX records should be valid after successful validation");
                continue;
            }
            // Links are skipped, so their long names are not needed.
            if typeflag == TypeFlag::GNULONGLINK {
                continue;
            }

            // Ignore directory entries, i.e. yield only regular files. Works
            // as filenames in tarballs are fully specified, e.g. dirA/dirB/file1
            let filename = long_name.take().unwrap_or_else(|| hdr.filename());
            if !hdr.is_regular_file(&filename) {
                debug!("Skipping non-regular entry of type {:?}", hdr.typeflag);
                continue;
            }

            return Some(ArchiveEntry::new(
                filename,
                self.payload(block_index, hdr),
                hdr,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TYPEFLAG_OFFSET, TarFormatOctal};
    use std::vec::Vec;

    #[test]
    #[rustfmt::skip]
    fn test_constructor_returns_error() {
        assert_eq!(
            TarArchiveRef::new(&[0]),
            Err(CorruptDataError::InvalidBlockSize)
        );
        assert_eq!(
            TarArchiveRef::new(&[]),
            Err(CorruptDataError::EmptyArchive)
        );
        assert_eq!(
            TarArchiveRef::new(&[0; BLOCKSIZE]),
            Err(CorruptDataError::MissingTerminator)
        );
        // Two zero blocks are a valid empty archive, like for TarStreamParser.
        assert!(TarArchiveRef::new(&[0; 2 * BLOCKSIZE]).is_ok());

        #[cfg(feature = "alloc")]
        {
            assert_eq!(
                TarArchive::new(vec![].into_boxed_slice()),
                Err(CorruptDataError::EmptyArchive)
            );
            assert_eq!(
                TarArchive::new(vec![0].into_boxed_slice()),
                Err(CorruptDataError::InvalidBlockSize)
            );
            assert!(TarArchive::new(vec![0; 2 * BLOCKSIZE].into_boxed_slice()).is_ok());
            assert_eq!(
                TarArchive::try_from(vec![0].into_boxed_slice()),
                Err(CorruptDataError::InvalidBlockSize)
            );
        };
    }

    #[test]
    fn test_header_iterator() {
        let archive = include_bytes!("../tests/gnu_tar_default.tar");
        let iter = TarArchiveRef::new(archive)
            .expect("test archive should pass validation")
            .headers();
        let names = iter
            .map(|(_i, hdr)| hdr.name.as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            names.as_slice(),
            &[
                "bye_world_513b.txt",
                "hello_world_513b.txt",
                "hello_world.txt",
            ]
        );
    }

    /// The test here is that no panics occur.
    #[test]
    fn test_print_archive_headers() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");

        let iter = TarArchiveRef::new(data)
            .expect("test archive should pass validation")
            .headers();
        let entries = iter.map(|(_, hdr)| hdr).collect::<Vec<_>>();
        println!("{entries:#?}");
    }

    /// The test here is that no panics occur.
    #[test]
    fn test_print_archive_list() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        println!("{entries:#?}");
    }

    /// Tests weird (= invalid, corrupt) tarballs that are bundled in a tarball.
    ///
    /// The tarballs originate from a fuzzing process by a GitHub contributor
    /// [0].
    ///
    /// The outer archive is valid, while every nested fuzzer input must fail
    /// checksum validation without panicking.
    ///
    /// [0] https://github.com/phip1611/tar-no-std/issues/12#issuecomment-2092632090
    #[test]
    fn test_weird_fuzzing_tarballs() {
        /*std::env::set_var("RUST_LOG", "trace");
        std::env::set_var("RUST_LOG_STYLE", "always");
        env_logger::init();*/

        let main_tarball =
            TarArchiveRef::new(include_bytes!("../tests/weird_fuzzing_tarballs.tar"))
                .expect("archive containing fuzzing inputs should pass validation");

        // Every corpus entry corrupts a header checksum. Check the validation
        // category without coupling this test to the exact header that is
        // reached first.
        let mut input_count = 0;
        for fuzzing_input in main_tarball.entries() {
            let result = TarArchiveRef::new(fuzzing_input.data());
            assert!(
                // TODO we should fix the checksum of at least some of these
                // to exercise more code paths.
                matches!(result, Err(CorruptDataError::InvalidChecksum { .. })),
                "fuzzing input {:?} should fail checksum validation: {result:?}",
                fuzzing_input.filename(),
            );
            input_count += 1;
        }
        assert_eq!(input_count, 32);
    }

    /// Tests to read the entries from existing archives in various Tar flavors.
    #[test]
    fn test_archive_entries() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_gnu.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_oldgnu.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        // PAX metadata is ignored; these files also have usable regular
        // headers.
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_pax.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_posix.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_ustar.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_v7.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);
    }

    /// Tests to read the entries from an existing tarball with a directory in
    /// it.
    #[test]
    fn test_archive_with_long_dir_entries() {
        // tarball created with:
        //     $ cd tests; gtar --format=ustar -cf gnu_tar_ustar_long.tar 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234/ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_ustar_long.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();

        assert_eq!(entries.len(), 2);
        // Maximum length of a directory and name when the directory itself is tar'd
        assert_entry_content(
            &entries[0],
            "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678/ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ",
            7,
        );
        // Maximum length of a directory and name when only the file is tar'd.
        assert_entry_content(
            &entries[1],
            "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234/ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ",
            7,
        );
    }

    #[test]
    fn test_archive_with_deep_dir_entries() {
        // tarball created with:
        //     $ cd tests; gtar --format=ustar -cf gnu_tar_ustar_deep.tar 0123456789
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_ustar_deep.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();

        assert_eq!(entries.len(), 1);
        assert_entry_content(
            &entries[0],
            "0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/empty",
            0,
        );
    }

    #[test]
    fn test_default_archive_with_dir_entries() {
        // tarball created with:
        //     $ gtar -cf tests/gnu_tar_default_with_dir.tar --exclude '*.tar' --exclude '012345678*' tests
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default_with_dir.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();

        assert_archive_with_dir_content(&entries);
    }

    #[test]
    fn test_ustar_archive_with_dir_entries() {
        // tarball created with:
        //     $(osx) tar -cf tests/mac_tar_ustar_with_dir.tar --format=ustar --exclude '*.tar' --exclude '012345678*' tests
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/mac_tar_ustar_with_dir.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();

        assert_archive_with_dir_content(&entries);
    }

    #[test]
    fn test_data_fills_entire_block() {
        // header, data block, 2 zero blocks
        let mut data = [0_u8; 4 * BLOCKSIZE];

        // Fill payload: We have a full block
        {
            data[BLOCKSIZE..BLOCKSIZE * 2].fill(0xff);
        }

        // Write header
        {
            // SAFETY: We know that the header is at the beginning of the data.
            let hdr = unsafe { data.as_mut_ptr().cast::<PosixHeader>().as_mut().unwrap() };
            let blocksize_octal = "1000\0\0\0\0\0\0\0\0" /* BLOCKSIZE */;
            let blocksize_octal_bytes: [u8; 12] = {
                let mut val = [0; 12];
                val.copy_from_slice(blocksize_octal.as_bytes());
                val
            };
            hdr.size = TarFormatOctal::new(blocksize_octal_bytes);
            write_checksum(hdr);
        }
        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.iter().all(|&v| v == 0xff));
    }

    #[test]
    fn test_constructor_rejects_invalid_header_checksum() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[0] ^= 0xff;

        assert_eq!(
            TarArchiveRef::new(data.as_slice()),
            Err(CorruptDataError::InvalidChecksum { block_index: 0 })
        );
    }

    #[test]
    fn test_constructor_rejects_invalid_type_flag() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        // Unknown type flag.
        data[TYPEFLAG_OFFSET] = b'?';
        write_first_header_checksum(&mut data);

        assert_eq!(
            TarArchiveRef::new(data.as_slice()),
            Err(CorruptDataError::InvalidTypeFlag { block_index: 0 })
        );
    }

    #[test]
    fn test_constructor_rejects_invalid_payload_size() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[124] = 0xff;
        write_first_header_checksum(&mut data);

        assert_eq!(
            TarArchiveRef::new(data.as_slice()),
            Err(CorruptDataError::InvalidPayloadSize { block_index: 0 })
        );
    }

    #[test]
    fn test_constructor_rejects_payload_beyond_archive() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[124..136].copy_from_slice(b"77777777777\0");
        write_first_header_checksum(&mut data);

        assert_eq!(
            TarArchiveRef::new(data.as_slice()),
            Err(CorruptDataError::PayloadExtendsBeyondArchive { block_index: 0 })
        );
    }

    #[test]
    fn test_constructor_rejects_missing_end_marker() {
        let mut data = [0; 2 * BLOCKSIZE];
        data[BLOCKSIZE] = 1;

        assert_eq!(
            TarArchiveRef::new(&data),
            Err(CorruptDataError::MissingTerminator)
        );
    }

    #[test]
    fn test_header_outlives_entry() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default.tar")).unwrap();
        // Like `data()`, the header borrows the archive, not the entry.
        let header = archive.entries().next().unwrap().posix_header();
        assert_eq!(header.name.as_str(), Ok("bye_world_513b.txt"));
    }

    #[test]
    fn test_numbers_with_leading_spaces() {
        // Setup: right-align the size and the checksum with spaces, like some
        // old Tar implementations do.
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[124..136].copy_from_slice(b"       1001 ");
        // SAFETY: the data has at least one complete header block.
        let hdr = unsafe { data.as_mut_ptr().cast::<PosixHeader>().as_mut().unwrap() };
        let checksum = format!("{:7o}\0", hdr.computed_checksum());
        hdr.cksum = TarFormatOctal::new(checksum.as_bytes().try_into().unwrap());

        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entry = archive.entries().next().unwrap();
        assert_eq!(entry.filename().as_str(), Ok("bye_world_513b.txt"));
        assert_eq!(entry.size(), 513);
    }

    #[test]
    fn test_old_style_directory_is_skipped() {
        // Setup: turn the directory into an old-style one, i.e. a regular file
        // whose name ends with a slash.
        let mut data = include_bytes!("../tests/gnu_tar_default_with_dir.tar").to_vec();
        assert_eq!(&data[..7], b"tests/\0");
        data[TYPEFLAG_OFFSET] = TypeFlag::AREGTYPE.to_byte();
        write_first_header_checksum(&mut data);

        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entry = archive.entries().next().unwrap();
        assert_eq!(entry.filename().as_str(), Ok("tests/hello_world.txt"));
    }

    /// Tests an archive with GNU long names for two directories and a file,
    /// and a GNU long link name for a symlink.
    ///
    /// The archives with long names were created with GNU tar 1.35:
    /// `tar --format=gnu --owner=0 --group=0 --numeric-owner --mtime=@0
    /// --sort=name -b1 -cf <archive> .`
    #[test]
    fn test_gnu_long_names() {
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_gnu_long_names.tar")).unwrap();
        let long_name = format!("./{0}/{0}/long_name.txt", "d".repeat(48));
        let entries = archive
            .entries()
            .map(|entry| (entry.filename(), entry.data_as_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0.as_str(), Ok(long_name.as_str()));
        assert_eq!(entries[0].1, "long name\n");
        // The long link name of the symlink in between is not applied.
        assert_eq!(entries[1].0.as_str(), Ok("./short.txt"));
        assert_eq!(entries[1].1, "short\n");
    }

    #[test]
    fn test_rejects_too_long_gnu_long_name() {
        // The 303 bytes long name of the file is at block 7.
        assert_eq!(
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_gnu_too_long_name.tar")),
            Err(CorruptDataError::FilenameTooLong { block_index: 7 })
        );
    }

    #[test]
    fn test_vendor_entry_is_skipped() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        // Vendor-specific entry.
        data[TYPEFLAG_OFFSET] = b'I';
        write_first_header_checksum(&mut data);

        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entry = archive.entries().next().unwrap();
        assert_eq!(entry.filename().as_str(), Ok("hello_world_513b.txt"));
    }

    #[test]
    fn test_rejects_gnu_sparse_file() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        // GNU sparse file.
        data[TYPEFLAG_OFFSET] = b'S';
        write_first_header_checksum(&mut data);

        assert_eq!(
            TarArchiveRef::new(data.as_slice()),
            Err(CorruptDataError::InvalidTypeFlag { block_index: 0 })
        );
    }

    /// Tests that the volume label, whose size field is empty, is skipped.
    ///
    /// The archive was created like the ones with GNU long names, with the
    /// additional `--label=VOLUME`.
    #[test]
    fn test_gnu_volume_label_is_skipped() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_gnu_label.tar")).unwrap();
        let entries = archive
            .entries()
            .map(|entry| (entry.filename(), entry.data_as_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.as_str(), Ok("file.txt"));
        assert_eq!(entries[0].1, "labeled\n");
    }

    /// Tests that PAX paths are applied, for long paths and for UTF-8 names.
    ///
    /// The archives with PAX paths were created with GNU tar 1.35:
    ///
    /// ```text
    /// tar --format=posix --owner=0 --group=0 --numeric-owner --mtime=@0 \
    ///     --sort=name -b1 --pax-option=delete=atime,delete=ctime \
    ///     --pax-option=exthdr.name=%d/PaxHeaders/%f -cf <archive> .
    /// ```
    #[test]
    fn test_pax_paths() {
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_posix_long_names.tar")).unwrap();
        let long_name = format!("./{0}/{0}/long_name.txt", "d".repeat(48));
        let entries = archive
            .entries()
            .map(|entry| (entry.filename(), entry.data_as_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0.as_str(), Ok(long_name.as_str()));
        assert_eq!(entries[0].1, "long name\n");
        assert_eq!(entries[1].0.as_str(), Ok("./short.txt"));
        assert_eq!(entries[2].0.as_str(), Ok("./utf8_äöü_日本.txt"));
        assert_eq!(entries[2].1, "utf8 name\n");
    }

    #[test]
    fn test_rejects_too_long_pax_path() {
        // The 300 bytes long path of the file is at block 7.
        assert_eq!(
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_posix_too_long_name.tar")),
            Err(CorruptDataError::FilenameTooLong { block_index: 7 })
        );
    }

    #[test]
    fn test_contiguous_file_is_regular_file() {
        let mut data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
        data[TYPEFLAG_OFFSET] = TypeFlag::CONTTYPE.to_byte();
        write_first_header_checksum(&mut data);

        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entry = archive.entries().next().unwrap();
        assert_eq!(entry.filename().as_str(), Ok("bye_world_513b.txt"));
        assert_eq!(entry.size(), 513);
    }

    /// Like [`test_archive_entries`] but with additional `alloc` functionality.
    #[cfg(feature = "alloc")]
    #[test]
    fn test_archive_entries_alloc() {
        let data = include_bytes!("../tests/gnu_tar_default.tar")
            .to_vec()
            .into_boxed_slice();
        let archive = TarArchive::new(data.clone()).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        // Test that the archive can be transformed into owned heap data.
        assert_eq!(data, archive.into());
    }

    /// Test that the entry's contents match the expected content.
    fn assert_entry_content(entry: &ArchiveEntry, filename: &str, size: usize) {
        assert_eq!(entry.filename().as_str(), Ok(filename));
        assert_eq!(entry.size(), size);
        assert_eq!(entry.data().len(), size);
    }

    fn write_checksum(hdr: &mut PosixHeader) {
        let checksum = format!("{:06o}\0 ", hdr.computed_checksum());
        let mut checksum_bytes = [0; 8];
        checksum_bytes.copy_from_slice(checksum.as_bytes());
        hdr.cksum = TarFormatOctal::new(checksum_bytes);
    }

    fn write_first_header_checksum(data: &mut [u8]) {
        // SAFETY: all callers provide at least one complete header block.
        let hdr = unsafe { data.as_mut_ptr().cast::<PosixHeader>().as_mut().unwrap() };
        write_checksum(hdr);
    }

    /// Tests that the parsed archive matches the expected order.
    ///
    /// The tarballs in the tests directory were created once by me with files
    /// in the order specified in this test.
    fn assert_archive_content(entries: &[ArchiveEntry]) {
        use crate::ModeFlags;
        let permissions = ModeFlags::OwnerRead
            | ModeFlags::OwnerWrite
            | ModeFlags::OwnerExec
            | ModeFlags::GroupRead
            | ModeFlags::GroupWrite
            | ModeFlags::GroupExec
            | ModeFlags::OthersRead
            | ModeFlags::OthersWrite
            | ModeFlags::OthersExec;
        let rw_rw_r__ = ModeFlags::OwnerRead
            | ModeFlags::OwnerWrite
            | ModeFlags::GroupRead
            | ModeFlags::GroupWrite
            | ModeFlags::OthersRead;
        // Rust complains otherwise, but this is intentionally written this way.
        #[expect(non_snake_case)]
        let rw_r__r__ = ModeFlags::OwnerRead
            | ModeFlags::OwnerWrite
            | ModeFlags::GroupRead
            | ModeFlags::OthersRead;

        assert_eq!(entries.len(), 3);

        assert_entry_content(&entries[0], "bye_world_513b.txt", 513);
        assert_eq!(
            entries[0].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/bye_world_513b.txt").replace("\r\n", "\n")
        );
        assert_eq!(
            entries[0]
                .posix_header()
                .mode
                .to_flags()
                .unwrap()
                .intersection(permissions),
            rw_rw_r__
        );

        // Test that an entry that needs two 512 byte data blocks is read
        // properly.
        assert_entry_content(&entries[1], "hello_world_513b.txt", 513);
        assert_eq!(
            entries[1].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/hello_world_513b.txt").replace("\r\n", "\n")
        );
        assert_eq!(
            entries[1]
                .posix_header()
                .mode
                .to_flags()
                .unwrap()
                .intersection(permissions),
            rw_rw_r__
        );

        assert_entry_content(&entries[2], "hello_world.txt", 12);
        assert_eq!(
            entries[2].data_as_str().expect("Should be valid UTF-8"),
            "Hello World\n",
            "file content must match"
        );
        assert_eq!(
            entries[2]
                .posix_header()
                .mode
                .to_flags()
                .unwrap()
                .intersection(permissions),
            rw_r__r__
        );
    }

    /// Tests that the parsed archive matches the expected order and the
    /// filenames include the directory name.
    ///
    /// The tarballs in the tests directory were created once by me with files
    /// in the order specified in this test.
    fn assert_archive_with_dir_content(entries: &[ArchiveEntry]) {
        assert_eq!(entries.len(), 3);

        assert_entry_content(&entries[0], "tests/hello_world.txt", 12);
        assert_eq!(
            entries[0].data_as_str().expect("Should be valid UTF-8"),
            "Hello World\n",
            "file content must match"
        );

        // Test that an entry that needs two 512 byte data blocks is read
        // properly.
        assert_entry_content(&entries[1], "tests/bye_world_513b.txt", 513);
        assert_eq!(
            entries[1].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/bye_world_513b.txt").replace("\r\n", "\n")
        );

        assert_entry_content(&entries[2], "tests/hello_world_513b.txt", 513);
        assert_eq!(
            entries[2].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/hello_world_513b.txt").replace("\r\n", "\n")
        );
    }
}
