/*
MIT License

Copyright (c) 2021 Philipp Schuster

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
//! Module for [`TarArchive`].

use crate::header::PosixHeader;
use crate::{TypeFlag, BLOCKSIZE};
use arrayvec::ArrayString;
use core::fmt::{Debug, Formatter};
use core::str::FromStr;

/// Describes an entry in an archive.
/// Currently only supports files but no directories.
pub struct ArchiveEntry<'a> {
    filename: ArrayString<100>,
    data: &'a [u8],
    size: usize,
}

#[allow(unused)]
impl<'a> ArchiveEntry<'a> {
    pub const fn new(filename: ArrayString<100>, data: &'a [u8]) -> Self {
        ArchiveEntry {
            filename,
            data,
            size: data.len(),
        }
    }

    /// Filename of the entry. Max 99 characters.
    pub const fn filename(&self) -> ArrayString<100> {
        self.filename
    }

    /// Data of the file.
    pub const fn data(&self) -> &'a [u8] {
        self.data
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

/// Wrapper type around the bytes, which represents an archive.
#[derive(Debug)]
pub struct TarArchive<'a> {
    data: &'a [u8],
}

#[allow(unused)]
impl<'a> TarArchive<'a> {
    /// Interprets the provided byte array as Tar archive.
    pub fn new(data: &'a [u8]) -> Self {
        assert_eq!(
            data.len() % BLOCKSIZE,
            0,
            "data must be a multiple of BLOCKSIZE={}",
            BLOCKSIZE
        );
        Self { data }
    }

    /// Iterates over all entries of the TAR Archive.
    /// Returns items of type [`ArchiveEntry`].
    pub const fn entries(&self) -> ArchiveIterator {
        ArchiveIterator::new(self)
    }
}

/// Iterator over the files. Each iteration step starts
/// at the next Tar header entry.
#[derive(Debug)]
pub struct ArchiveIterator<'a> {
    archive: &'a TarArchive<'a>,
    block_index: usize,
}

impl<'a> ArchiveIterator<'a> {
    pub const fn new(archive: &'a TarArchive<'a>) -> Self {
        Self {
            archive,
            block_index: 0,
        }
    }

    /// Returns a reference to the next Header.
    fn next_hdr(&self, block_index: usize) -> &'a PosixHeader {
        let hdr_ptr = &self.archive.data[block_index * BLOCKSIZE];
        unsafe { (hdr_ptr as *const u8).cast::<PosixHeader>().as_ref() }.unwrap()
    }
}

impl<'a> Iterator for ArchiveIterator<'a> {
    type Item = ArchiveEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_index * BLOCKSIZE >= self.archive.data.len() {
            log::warn!("Reached end of Tar archive data without finding zero/end blocks!");
            return None;
        }

        let hdr = self.next_hdr(self.block_index);

        // check if we found end of archive
        if hdr.is_zero_block() {
            let next_hdr = self.next_hdr(self.block_index + 1);
            if next_hdr.is_zero_block() {
                // gracefully terminated Archive
                log::debug!("End of Tar archive with two zero blocks!");
            } else {
                log::warn!("Zero block found at end of Tar archive, but only one instead of two!");
            }
            // end of archive
            return None;
        }

        if hdr.typeflag != TypeFlag::AREGTYPE && hdr.typeflag != TypeFlag::REGTYPE {
            log::warn!(
                "Found entry of type={:?}, but only files are supported",
                hdr.typeflag
            );
            return None;
        }

        if hdr.name.is_empty() {
            log::warn!("Found empty file name",);
        }

        // fetch data of file from next block(s)
        let data_block_count = hdr.payload_block_count();
        // +1: skip hdr block itself and start at data!
        // i_begin is the byte begin index of this file in the array of the whole archive
        let i_begin = (self.block_index + 1) * BLOCKSIZE;
        // i_end is the exclusive byte end index of the data of the current file
        let i_end = i_begin + data_block_count * BLOCKSIZE;
        let file_block_bytes = &self.archive.data[i_begin..i_end];
        // because each block is 512 bytes long, the file is not necessarily a multiple of 512 bytes
        let file_bytes = &file_block_bytes[0..hdr.size.val()];

        // in next iteration: start at next Archive entry header
        // +1 for current hdr block itself + all data blocks
        self.block_index += data_block_count + 1;

        Some(ArchiveEntry::new(
            ArrayString::from_str(hdr.name.as_string().as_str()).unwrap(),
            file_bytes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str;
    use std::vec::Vec;

    #[test]
    fn test_archive_list() {
        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_default.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        println!("{:#?}", entries);
    }

    #[test]
    fn test_archive_entries() {
        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_default.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_gnu.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_oldgnu.tar"));
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

        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_ustar.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);

        let archive = TarArchive::new(include_bytes!("../tests/gnu_tar_v7.tar"));
        let entries = archive.entries().collect::<Vec<_>>();
        assert_archive_content(&entries);
    }

    fn assert_archive_content(entries: &[ArchiveEntry]) {
        assert_eq!(entries.len(), 3);
        // order in that I stored the files into the archive
        assert_eq!(entries[0].filename().as_str(), "bye_world_513b.txt");
        assert_eq!(entries[0].size(), 513);
        assert_eq!(entries[0].data().len(), 513);
        assert_eq!(
            unsafe { str::from_utf8_unchecked(entries[0].data) },
            include_str!("../tests/bye_world_513b.txt")
        );

        assert_eq!(entries[1].filename().as_str(), "hello_world_513b.txt");
        assert_eq!(entries[1].size(), 513);
        assert_eq!(entries[1].data().len(), 513);
        assert_eq!(
            unsafe { str::from_utf8_unchecked(entries[1].data) },
            include_str!("../tests/hello_world_513b.txt")
        );

        assert_eq!(entries[2].filename().as_str(), "hello_world.txt");
        assert_eq!(entries[2].size(), 12);
        assert_eq!(entries[2].data().len(), 12);
        assert_eq!(
            unsafe { str::from_utf8_unchecked(entries[2].data) },
            "Hello World\n",
            "file content must match"
        );
    }
}
