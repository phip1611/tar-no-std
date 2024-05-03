/*
MIT License

Copyright (c) 2023 Philipp Schuster

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
use crate::{TypeFlag, BLOCKSIZE, POSIX_1003_MAX_FILENAME_LEN};
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter};
use core::str::Utf8Error;
use log::warn;

/// Describes an entry in an archive.
/// Currently only supports files but no directories.
pub struct ArchiveEntry<'a> {
    filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>,
    data: &'a [u8],
    size: usize,
}

#[allow(unused)]
impl<'a> ArchiveEntry<'a> {
    const fn new(filename: TarFormatString<POSIX_1003_MAX_FILENAME_LEN>, data: &'a [u8]) -> Self {
        ArchiveEntry {
            filename,
            data,
            size: data.len(),
        }
    }

    /// Filename of the entry with a maximum of 100 characters (including the
    /// terminating NULL-byte).
    pub const fn filename(&self) -> TarFormatString<{ POSIX_1003_MAX_FILENAME_LEN }> {
        self.filename
    }

    /// Data of the file.
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Data of the file as string slice, if data is valid UTF-8.
    #[allow(clippy::missing_const_for_fn)]
    pub fn data_as_str(&self) -> Result<&'a str, Utf8Error> {
        core::str::from_utf8(self.data)
    }

    /// Filesize in bytes.
    pub const fn size(&self) -> usize {
        self.size
    }
}

impl<'a> Debug for ArchiveEntry<'a> {
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CorruptDataError;

impl Display for CorruptDataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[cfg(feature = "unstable")]
impl core::error::Error for CorruptDataError {}

/// Type that owns bytes on the heap, that represents a Tar archive.
/// Unlike [`TarArchiveRef`], this type is useful, if you need to own the
/// data as long as you need the archive, but no longer.
///
/// This is only available with the `alloc` feature of this crate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchive {
    data: Box<[u8]>,
}

#[cfg(feature = "alloc")]
impl TarArchive {
    /// Creates a new archive type, that owns the data on the heap. The provided byte array is
    /// interpreted as bytes in Tar archive format.
    pub fn new(data: Box<[u8]>) -> Result<Self, CorruptDataError> {
        let is_malformed = (data.len() % BLOCKSIZE) != 0;
        (!data.is_empty() && !is_malformed)
            .then_some(Self { data })
            .ok_or(CorruptDataError)
    }

    /// Iterates over all entries of the Tar archive.
    /// Returns items of type [`ArchiveEntry`].
    /// See also [`ArchiveIterator`].
    pub fn entries(&self) -> ArchiveIterator {
        ArchiveIterator::new(self.data.as_ref())
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

/// Wrapper type around bytes, which represents a Tar archive.
/// Unlike [`TarArchive`], this uses only a reference to the data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchiveRef<'a> {
    data: &'a [u8],
}

#[allow(unused)]
impl<'a> TarArchiveRef<'a> {
    /// Creates a new archive wrapper type. The provided byte array is
    /// interpreted as bytes in Tar archive format.
    pub fn new(data: &'a [u8]) -> Result<Self, CorruptDataError> {
        let is_malformed = (data.len() % BLOCKSIZE) != 0;
        (!data.is_empty() && !is_malformed)
            .then_some(Self { data })
            .ok_or(CorruptDataError)
    }

    /// Iterates over all entries of the Tar archive.
    /// Returns items of type [`ArchiveEntry`].
    /// See also [`ArchiveIterator`].
    pub const fn entries(&self) -> ArchiveIterator {
        ArchiveIterator::new(self.data)
    }
}

/// Iterator over the files of the archive. Each iteration starts
/// at the next Tar header entry.
#[derive(Debug)]
pub struct ArchiveIterator<'a> {
    archive_data: &'a [u8],
    block_index: usize,
}

impl<'a> ArchiveIterator<'a> {
    pub const fn new(archive: &'a [u8]) -> Self {
        Self {
            archive_data: archive,
            block_index: 0,
        }
    }

    /// Returns a reference to the next Header.
    fn next_hdr(&self, block_index: usize) -> &'a PosixHeader {
        let hdr_ptr = &self.archive_data[block_index * BLOCKSIZE];
        unsafe { (hdr_ptr as *const u8).cast::<PosixHeader>().as_ref() }.unwrap()
    }
}

impl<'a> Iterator for ArchiveIterator<'a> {
    type Item = ArchiveEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_index * BLOCKSIZE >= self.archive_data.len() {
            warn!("Reached end of Tar archive data without finding zero/end blocks!");
            return None;
        }

        let mut hdr = self.next_hdr(self.block_index);

        loop {
            // check if we found end of archive
            if hdr.is_zero_block() {
                let next_hdr = self.next_hdr(self.block_index + 1);
                if next_hdr.is_zero_block() {
                    // gracefully terminated Archive
                    log::debug!("End of Tar archive with two zero blocks!");
                } else {
                    log::warn!(
                        "Zero block found at end of Tar archive, but only one instead of two!"
                    );
                }
                // end of archive
                return None;
            }

            // Ignore directory entries, i.e. yield only regular files. Works as
            // filenames in tarballs are fully specified, e.g. dirA/dirB/file1
            if hdr.typeflag != TypeFlag::DIRTYPE {
                break;
            }

            // in next iteration: start at next Archive entry header
            // +1 for current hdr block itself + all data blocks
            let data_block_count: usize = hdr.payload_block_count().unwrap();
            self.block_index += data_block_count + 1;
            hdr = self.next_hdr(self.block_index);
        }

        if hdr.typeflag != TypeFlag::AREGTYPE && hdr.typeflag != TypeFlag::REGTYPE {
            log::warn!(
                "Found entry of type={:?}, but only files are supported",
                hdr.typeflag
            );
            return None;
        }

        if hdr.name.is_empty() {
            warn!("Found empty file name",);
        }

        let hdr_size = hdr.size.as_number::<usize>();
        if let Err(e) = hdr_size {
            warn!("Can't parse the file size from the header block. Stop iterating Tar archive. {e:#?}");
            return None;
        }
        let hdr_size = hdr_size.unwrap();

        // Fetch data of file from next block(s).
        // .unwrap() is fine as we checked that hdr.size().val() is valid
        // above
        let data_block_count = hdr.payload_block_count().unwrap();

        // +1: skip hdr block itself and start at data!
        // i_begin is the byte begin index of this file in the array of the whole archive
        let i_begin = (self.block_index + 1) * BLOCKSIZE;
        // i_end is the exclusive byte end index of the data of the current file
        let i_end = i_begin + data_block_count * BLOCKSIZE;
        let file_block_bytes = &self.archive_data[i_begin..i_end];
        // Each block is 512 bytes long, but the file size is not necessarily a
        // multiple of 512.
        let file_bytes = &file_block_bytes[0..hdr_size];

        // in next iteration: start at next Archive entry header
        // +1 for current hdr block itself + all data blocks
        self.block_index += data_block_count + 1;

        let mut filename: TarFormatString<256> =
            TarFormatString::<POSIX_1003_MAX_FILENAME_LEN>::new([0; POSIX_1003_MAX_FILENAME_LEN]);
        if hdr.magic.as_str().unwrap() == "ustar" && hdr.version.as_str().unwrap() == "00" && !hdr.prefix.is_empty() {
            filename.append(&hdr.prefix);
            filename.append(&TarFormatString::<1>::new([b'/']));
        }
        filename.append(&hdr.name);
        Some(ArchiveEntry::new(filename, file_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    #[rustfmt::skip]
    fn test_constructor_returns_error() {
        assert_eq!(TarArchiveRef::new(&[0]), Err(CorruptDataError));
        assert_eq!(TarArchiveRef::new(&[]), Err(CorruptDataError));
        assert!(TarArchiveRef::new(&[0; BLOCKSIZE]).is_ok());

        #[cfg(feature = "alloc")]
        {
            assert_eq!(TarArchive::new(vec![].into_boxed_slice()), Err(CorruptDataError));
            assert_eq!(TarArchive::new(vec![0].into_boxed_slice()), Err(CorruptDataError));
            assert!(TarArchive::new(vec![0; BLOCKSIZE].into_boxed_slice()).is_ok());
        };
    }

    #[test]
    fn test_archive_list() {
        let archive = TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();
        println!("{:#?}", entries);
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
        assert_entry_content(&entries[0], "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678/ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ", 7);
        // Maximum length of a directory and name when only the file is tar'd.
        assert_entry_content(&entries[1], "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234/ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ", 7);
    }

    #[test]
    fn test_archive_with_deep_dir_entries() {
        // tarball created with:
        //     $ cd tests; gtar --format=ustar -cf gnu_tar_ustar_deep.tar 0123456789
        let archive =
            TarArchiveRef::new(include_bytes!("../tests/gnu_tar_ustar_deep.tar")).unwrap();
        let entries = archive.entries().collect::<Vec<_>>();

        assert_eq!(entries.len(), 1);
        assert_entry_content(&entries[0], "0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/0123456789/empty", 0);
    }

    #[test]
    fn test_archive_with_dir_entries() {
        // tarball created with:
        //     $ gtar -cf tests/gnu_tar_default_with_dir.tar --exclude '*.tar' --exclude '012345678*' tests
        {
            let archive =
                TarArchiveRef::new(include_bytes!("../tests/gnu_tar_default_with_dir.tar"))
                    .unwrap();
            let entries = archive.entries().collect::<Vec<_>>();

            assert_archive_with_dir_content(&entries);
        }

        // tarball created with:
        //     $(osx) tar -cf tests/mac_tar_ustar_with_dir.tar --format=ustar --exclude '*.tar' --exclude '012345678*' tests
        {
            let archive =
                TarArchiveRef::new(include_bytes!("../tests/mac_tar_ustar_with_dir.tar")).unwrap();
            let entries = archive.entries().collect::<Vec<_>>();

            assert_archive_with_dir_content(&entries);
        }
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
        assert_eq!(entries.len(), 3);

        assert_entry_content(&entries[0], "bye_world_513b.txt", 513);
        assert_eq!(
            entries[0].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/bye_world_513b.txt").replace("\r\n", "\n")
        );

        // Test that an entry that needs two 512 byte data blocks is read
        // properly.
        assert_entry_content(&entries[1], "hello_world_513b.txt", 513);
        assert_eq!(
            entries[1].data_as_str().expect("Should be valid UTF-8"),
            // .replace: Ensure that the test also works on Windows
            include_str!("../tests/hello_world_513b.txt").replace("\r\n", "\n")
        );

        assert_entry_content(&entries[2], "hello_world.txt", 12);
        assert_eq!(
            entries[2].data_as_str().expect("Should be valid UTF-8"),
            "Hello World\n",
            "file content must match"
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
