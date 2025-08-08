/*
MIT License

Copyright (c) 2025 Philipp Schuster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
//! Module for [`TarArchiveRef`]. If the `alloc`-feature is enabled, this crate
//! also exports `TarArchive`, which owns data on the heap.

use crate::header::PosixHeader;
use crate::tar_format_types::TarFormatString;
use crate::{BLOCKSIZE, POSIX_1003_MAX_FILENAME_LEN};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter};
use core::str::Utf8Error;
use log::{error, warn};

/// Minimum amount of blocks that an archive must have to be considered sane.
/// - one header block
/// - two terminating zero blocks
pub const MIN_BLOCK_COUNT: usize = 3;

/// Describes an entry in an archive.
/// Currently only supports files but no directories.
pub struct ArchiveEntry<'a> {
    filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
    data: &'a [u8],
    size: usize,
    posix_header: &'a PosixHeader,
}

#[allow(unused)]
impl<'a> ArchiveEntry<'a> {
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

    /// Filename of the entry with a maximum of 100 characters (including the
    /// terminating NULL-byte).
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
    #[allow(clippy::missing_const_for_fn)]
    pub fn data_as_str(&self) -> Result<&'a str, Utf8Error> {
        core::str::from_utf8(self.data)
    }

    /// Filesize in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the [`PosixHeader`] for the entry.
    #[must_use]
    pub const fn posix_header(&self) -> &PosixHeader {
        self.posix_header
    }
}

impl Debug for ArchiveEntry<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchiveEntry")
            .field("filename", &self.filename().as_str())
            .field("size", &self.size())
            .field("data", &"<bytes>")
            .finish()
    }
}

/// The data is corrupt and doesn't present a valid Tar archive. Reasons for
/// that are:
/// - the data is empty
/// - the data is not a multiple of 512 (the BLOCKSIZE)
/// - the data is not at least [`MIN_BLOCK_COUNT`] blocks long
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CorruptDataError;

impl Display for CorruptDataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl core::error::Error for CorruptDataError {}

/// Type that owns bytes on the heap, that represents a Tar archive.
/// Unlike [`TarArchiveRef`], this type takes ownership of the data.
///
/// This is only available with the `alloc` feature of this crate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchive {
    data: Box<[u8]>,
}

#[cfg(feature = "alloc")]
impl TarArchive {
    /// Creates a new archive wrapper type. The provided byte array is
    /// interpreted as bytes in Tar archive format.
    ///
    /// Returns an error, if the sanity checks report problems.
    pub fn new(data: Box<[u8]>) -> Result<Self, CorruptDataError> {
        TarArchiveRef::validate(&data).map(|_| Self { data })
    }

    /// Iterates over all entries of the Tar archive.
    /// Returns items of type [`ArchiveEntry`].
    /// See also [`ArchiveEntryIterator`].
    #[must_use]
    pub fn entries(&self) -> ArchiveEntryIterator<'_> {
        ArchiveEntryIterator::new(self.data.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl From<Box<[u8]>> for TarArchive {
    fn from(data: Box<[u8]>) -> Self {
        Self::new(data).unwrap()
    }
}

#[cfg(feature = "alloc")]
impl From<TarArchive> for Box<[u8]> {
    fn from(ar: TarArchive) -> Self {
        ar.data
    }
}

/// Wrapper type around bytes, which represents a Tar archive. To iterate the
/// entries, use [`TarArchiveRef::entries`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchiveRef<'a> {
    data: &'a [u8],
}

#[allow(unused)]
impl<'a> TarArchiveRef<'a> {
    /// Creates a new archive wrapper type. The provided byte array is
    /// interpreted as bytes in Tar archive format.
    ///
    /// # Errors
    /// Returns an [`CorruptDataError`], if the sanity checks fail.
    pub fn new(data: &'a [u8]) -> Result<Self, CorruptDataError> {
        Self::validate(data).map(|()| Self { data })
    }

    fn validate(data: &'a [u8]) -> Result<(), CorruptDataError> {
        let is_malformed = (data.len() % BLOCKSIZE) != 0;
        let has_min_block_count = data.len() / BLOCKSIZE >= MIN_BLOCK_COUNT;
        (!data.is_empty() && !is_malformed && has_min_block_count)
            .then_some(())
            .ok_or(CorruptDataError)
    }

    /// Creates an [`ArchiveEntryIterator`].
    #[must_use]
    pub fn entries(&self) -> ArchiveEntryIterator<'a> {
        ArchiveEntryIterator::new(self.data)
    }
}

/// Iterates over the headers of the Tar archive.
#[derive(Debug)]
pub struct ArchiveHeaderIterator<'a> {
    archive_data: &'a [u8],
    next_hdr_block_index: usize,
}

impl<'a> ArchiveHeaderIterator<'a> {
    /// Creates a new iterator.
    ///
    /// # Panics
    /// Panics if the slice is zero or not a multiple of `BLOCKSIZE`.
    #[must_use]
    pub fn new(archive: &'a [u8]) -> Self {
        assert!(!archive.is_empty());
        assert_eq!(archive.len() % BLOCKSIZE, 0);
        Self {
            archive_data: archive,
            next_hdr_block_index: 0,
        }
    }

    /// Parse the memory at the given block as [`PosixHeader`].
    const fn block_as_header(&self, block_index: usize) -> &'a PosixHeader {
        unsafe {
            self.archive_data
                .as_ptr()
                .add(block_index * BLOCKSIZE)
                .cast::<PosixHeader>()
                .as_ref()
                .unwrap()
        }
    }
}

type BlockIndex = usize;

impl<'a> Iterator for ArchiveHeaderIterator<'a> {
    type Item = (BlockIndex, &'a PosixHeader);

    /// Returns the next header. Internally, it updates the necessary data
    /// structures to not read the same header multiple times.
    ///
    /// This returns `None` if either no further headers are found or if a
    /// header can't be parsed.
    fn next(&mut self) -> Option<Self::Item> {
        let total_block_count = self.archive_data.len() / BLOCKSIZE;
        if self.next_hdr_block_index >= total_block_count {
            warn!(
                "Invalid block index. Probably the Tar is corrupt: an header had an invalid payload size"
            );
            return None;
        }

        let hdr = self.block_as_header(self.next_hdr_block_index);
        let block_index = self.next_hdr_block_index;

        // Start at next block on next iteration.
        self.next_hdr_block_index += 1;

        // We only update the block index for types that have a payload.
        // In directory entries, for example, the size field has other
        // semantics. See spec.
        if let Ok(typeflag) = hdr.typeflag.try_to_type_flag() {
            if typeflag.is_regular_file() {
                let payload_block_count = hdr
                    .payload_block_count()
                    .inspect_err(|e| {
                        log::error!("Unparsable size ({e:?}) in header {hdr:#?}");
                    })
                    .ok()?;
                self.next_hdr_block_index += payload_block_count;
            }
        }

        Some((block_index, hdr))
    }
}

impl ExactSizeIterator for ArchiveEntryIterator<'_> {}

/// Iterator over the files of the archive.
///
/// Only regular files are supported, but not directories, links, or other
/// special types ([`crate::TypeFlag`]). The full path to files is reflected
/// in their file name.
#[derive(Debug)]
pub struct ArchiveEntryIterator<'a>(ArchiveHeaderIterator<'a>);

impl<'a> ArchiveEntryIterator<'a> {
    fn new(archive: &'a [u8]) -> Self {
        Self(ArchiveHeaderIterator::new(archive))
    }

    fn next_hdr(&mut self) -> Option<(BlockIndex, &'a PosixHeader)> {
        self.0.next()
    }
}

impl<'a> Iterator for ArchiveEntryIterator<'a> {
    type Item = ArchiveEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (mut block_index, mut hdr) = self.next_hdr()?;

        // Ignore directory entries, i.e. yield only regular files. Works as
        // filenames in tarballs are fully specified, e.g. dirA/dirB/file1
        while !hdr
            .typeflag
            .try_to_type_flag()
            .inspect_err(|e| error!("Invalid TypeFlag: {e:?}"))
            .ok()?
            .is_regular_file()
        {
            warn!(
                "Skipping entry of type {:?} (not supported yet)",
                hdr.typeflag
            );

            // Update properties.
            (block_index, hdr) = self.next_hdr()?;
        }

        // check if we found end of archive (two zero blocks)
        if hdr.is_zero_block() {
            if self.next_hdr()?.1.is_zero_block() {
                // found end
                return None;
            }

            panic!("should never have a missing double zero block: is the Tar archive corrupt?");
        }

        let payload_size: usize = hdr
            .size
            .as_number()
            .inspect_err(|e| error!("Can't parse the file size from the header. {e:#?}"))
            .ok()?;

        let idx_first_data_block = block_index + 1;
        let idx_begin = idx_first_data_block * BLOCKSIZE;
        let idx_end_exclusive = idx_begin + payload_size;

        // This doesn't subtract with overflow as we ensured a minimum size in
        // the constructor.
        let max_data_end_index_exclusive = self.0.archive_data.len() - 2 * BLOCKSIZE;
        if idx_end_exclusive > max_data_end_index_exclusive {
            warn!(
                "Invalid Tar. The size of the payload ({payload_size}) is larger than what is valid"
            );
            return None;
        }

        let file_bytes = &self.0.archive_data[idx_begin..idx_end_exclusive];

        let mut filename =
            TarFormatString::<POSIX_1003_MAX_FILENAME_LEN>::new([0; POSIX_1003_MAX_FILENAME_LEN]);

        // POXIS_1003 long filename check
        // https://docs.scinet.utoronto.ca/index.php/(POSIX_1003.1_USTAR)
        if (
            hdr.magic.as_str(),
            hdr.version.as_str(),
            hdr.prefix.is_empty(),
        ) == (Ok("ustar"), Ok("00"), false)
        {
            filename.append(&hdr.prefix);
            filename.append(&TarFormatString::<1>::new([b'/']));
        }
        filename.append(&hdr.name);
        Some(ArchiveEntry::new(filename, file_bytes, hdr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TarFormatOctal;
    use std::vec::Vec;

    #[test]
    #[rustfmt::skip]
    fn test_constructor_returns_error() {
        assert_eq!(TarArchiveRef::new(&[0]), Err(CorruptDataError));
        assert_eq!(TarArchiveRef::new(&[]), Err(CorruptDataError));
        assert!(TarArchiveRef::new(&[0; BLOCKSIZE * MIN_BLOCK_COUNT]).is_ok());

        #[cfg(feature = "alloc")]
        {
            assert_eq!(TarArchive::new(vec![].into_boxed_slice()), Err(CorruptDataError));
            assert_eq!(TarArchive::new(vec![0].into_boxed_slice()), Err(CorruptDataError));
            assert!(TarArchive::new(vec![0; BLOCKSIZE * MIN_BLOCK_COUNT].into_boxed_slice()).is_ok());
        };
    }

    #[test]
    fn test_header_iterator() {
        let archive = include_bytes!("../tests/gnu_tar_default.tar");
        let iter = ArchiveHeaderIterator::new(archive);
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
        )
    }

    /// The test here is that no panics occur.
    #[test]
    fn test_print_archive_headers() {
        let data = include_bytes!("../tests/gnu_tar_default.tar");

        let iter = ArchiveHeaderIterator::new(data);
        let entries = iter.map(|(_, hdr)| hdr).collect::<Vec<_>>();
        println!("{:#?}", entries);
    }

    /// The test here is that no panics occur.
    #[test]
    fn test_print_archive_list() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        println!("{:#?}", entries);
    }

    /// Tests various weird (= invalid, corrupt) tarballs that are bundled
    /// within this file. The tarball(s) originate from a fuzzing process from a
    /// GitHub contributor [0].
    ///
    /// The test succeeds if no panics occur.
    ///
    /// [0] https://github.com/phip1611/tar-no-std/issues/12#issuecomment-2092632090
    #[test]
    fn test_weird_fuzzing_tarballs() {
        /*std::env::set_var("RUST_LOG", "trace");
        std::env::set_var("RUST_LOG_STYLE", "always");
        env_logger::init();*/

        let main_tarball =
            TarArchiveRef::new(include_bytes!("../tests/weird_fuzzing_tarballs.tar")).unwrap();

        let mut all_entries = vec![];
        for tarball in main_tarball.entries() {
            let tarball = TarArchiveRef::new(tarball.data()).unwrap();
            for entry in tarball.entries() {
                all_entries.push(entry.filename());
            }
        }

        // Test succeeds if this works without a panic.
        for entry in all_entries {
            eprintln!("\"{entry:?}\",");
        }
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

        // UNSUPPORTED. Uses extensions.
        /*let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_pax.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);*/

        // UNSUPPORTED. Uses extensions.
        /*let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_posix.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);*/

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_ustar.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_v7.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);
    }

    /// Tests to read the entries from an existing tarball with a directory in it
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
            let hdr = unsafe { data.as_mut_ptr().cast::<PosixHeader>().as_mut().unwrap() };
            let blocksize_octal = "1000\0\0\0\0\0\0\0\0" /* BLOCKSIZE */;
            let blocksize_octal_bytes: [u8; 12] = {
                let mut val = [0; 12];
                val.copy_from_slice(blocksize_octal.as_bytes());
                val
            };
            hdr.size = TarFormatOctal::new(blocksize_octal_bytes);
        }
        let archive = TarArchiveRef::new(data.as_slice()).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.iter().all(|&v| v == 0xff));
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

    /// Tests that the parsed archive matches the expected order. The tarballs
    /// the tests directory were created once by me with files in the order
    /// specified in this test.
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
        #[allow(non_snake_case)]
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

    /// Tests that the parsed archive matches the expected order and the filename includes
    /// the directory name. The tarballs the tests directory were created once by me with files
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
