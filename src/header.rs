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
//! TAR header definition taken from <https://www.gnu.org/software/tar/manual/html_node/Standard.html>.
//! A Tar-archive is a collection of 512-byte sized blocks. Unfortunately there are several
//! TAR-like archive specifications. An Overview can be found here:
//! <https://www.gnu.org/software/tar/manual/html_node/Formats.html#Formats>
//!
//! This library focuses on extracting files from the GNU Tar format.

#![allow(non_upper_case_globals)]

use crate::BLOCKSIZE;
use arrayvec::ArrayString;
use core::fmt::{Debug, Formatter};

/// The file size is encoded as octal ASCII number inside a Tar header.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Size(StaticCString<12>);

impl Size {
    /// Returns the octal ASCII number as actual size in bytes.
    pub fn val(&self) -> usize {
        usize::from_str_radix(self.0.as_string().as_str(), 8).unwrap()
    }
}

impl Debug for Size {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_tuple("Size");
        debug.field(&self.val());
        debug.finish()
    }
}

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Mode(StaticCString<8>);

impl Mode {
    pub fn to_flags(self) -> ModeFlags {
        let octal_number_str = self.0.as_string();
        let bits = u64::from_str_radix(octal_number_str.as_str(), 8).unwrap();
        ModeFlags::from_bits(bits).unwrap()
    }
}

impl Debug for Mode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_tuple("Mode");
        debug.field(&self.to_flags());
        debug.finish()
    }
}

/// A C-String that is stored in a static array. All unused
/// chars must be a NULL-byte.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct StaticCString<const N: usize>([u8; N]);

#[allow(unused)]
impl<const N: usize> StaticCString<N> {
    /// Constructor.
    fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Returns the length of the string without NULL-byte.
    pub fn len(&self) -> usize {
        // not as efficient as it could be but negligible
        self.as_string().len()
    }

    /// Returns a string without null bytes.
    pub fn as_string(&self) -> ArrayString<N> {
        let mut string = ArrayString::new();
        // copy all bytes (=ASCII) into string
        self.0
            .clone()
            .iter()
            // remove all zero bytes; there is always one
            // zero byte at the end. Furtherore, the other
            // unused bytes are also zero, but not part of the
            // string.
            .filter(|x| **x != 0)
            .for_each(|b| string.push(*b as char));
        string
    }
}

impl<const N: usize> Debug for StaticCString<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_tuple("Name");
        let str = self.as_string();
        if str.len() == 0 {
            debug.field(&"<empty>");
        } else {
            debug.field(&str);
        }
        debug.finish()
    }
}

/// Header of the TAR format as specified by POSIX (POSIX 1003.1-1990.
/// "New" (version?) GNU Tar versions use this archive format by default.
/// (<https://www.gnu.org/software/tar/manual/html_node/Formats.html#Formats>).
///
/// Each file is started by such a header, that describes the size and
/// the file name. After that, the file content stands in chunks of 512 bytes.
/// The number of bytes can be derived from the file size.
///
/// This is also mostly compatible with the "Ustar"-header and the "GNU format".
/// Because this library only needs to fetch data and filename, we don't need
/// further checks.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct PosixHeader {
    /// Name. There is always a null byte, therefore
    /// the max len is 99.
    pub name: StaticCString<100>,
    pub mode: Mode,
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    // confusing; size is stored as ASCII string
    pub size: Size,
    pub mtime: [u8; 12],
    pub cksum: [u8; 8],
    pub typeflag: TypeFlag,
    /// Name. There is always a null byte, therefore
    /// the max len is 99.
    pub linkname: StaticCString<100>,
    pub magic: StaticCString<6>,
    pub version: StaticCString<2>,
    /// Username. There is always a null byte, therefore
    /// the max len is N-1.
    pub uname: StaticCString<32>,
    /// Groupname. There is always a null byte, therefore
    /// the max len is N-1.
    pub gname: StaticCString<32>,
    pub dev_major: [u8; 8],
    pub dev_minor: [u8; 8],
    /// There is always a null byte, therefore
    /// the max len is N-1.
    pub prefix: StaticCString<155>,
    // padding => to BLOCKSIZE bytes
    pub _pad: [u8; 12],
}

impl PosixHeader {
    /// Returns the number of blocks that are required to
    /// read the whole file content.
    pub fn payload_block_count(&self) -> usize {
        let div = self.size.val() / BLOCKSIZE;
        let modulo = self.size.val() % BLOCKSIZE;
        if modulo > 0 {
            (div + 1) as usize
        } else {
            div as usize
        }
    }

    /// A Tar archive is terminated, if a end-of-archive entry, which consists of two 512 blocks
    /// of zero bytes, is found.
    pub fn is_zero_block(&self) -> bool {
        let ptr = self as *const Self as *const u8;
        let self_bytes = unsafe { core::slice::from_raw_parts(ptr, BLOCKSIZE) };
        self_bytes.iter().filter(|x| **x == 0).count() == BLOCKSIZE
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
#[allow(unused)]
pub enum TypeFlag {
    /// Represents a regular file. In order to be compatible with older versions of tar, a typeflag
    /// value of AREGTYPE should be silently recognized as a regular file. New archives should be
    /// created using REGTYPE. Also, for backward compatibility, tar treats a regular file whose
    /// name ends with a slash as a directory.
    REGTYPE = b'0',
    /// Represents a regular file. In order to be compatible with older versions of tar, a typeflag
    /// value of AREGTYPE should be silently recognized as a regular file. New archives should be
    /// created using REGTYPE. Also, for backward compatibility, tar treats a regular file whose
    /// name ends with a slash as a directory.
    AREGTYPE = b'\0',
    /// This flag represents a file linked to another file, of any type, previously archived. Such
    /// files are identified in Unix by each file having the same device and inode number. The
    /// linked-to name is specified in the linkname field with a trailing null.
    LINK = 1,
    /// This represents a symbolic link to another file. The linked-to name is specified in the
    /// linkname field with a trailing null.
    SYMTYPE = 2,
    /// Represents character special files and block special files respectively. In this case the
    /// devmajor and devminor fields will contain the major and minor device numbers respectively.
    /// Operating systems may map the device specifications to their own local specification, or
    /// may ignore the entry.
    CHRTYPE = 3,
    /// Represents character special files and block special files respectively. In this case the
    /// devmajor and devminor fields will contain the major and minor device numbers respectively.
    /// Operating systems may map the device specifications to their own local specification, or
    /// may ignore the entry.
    BLKTYPE = 4,
    /// This flag specifies a directory or sub-directory. The directory name in the name field
    /// should end with a slash. On systems where disk allocation is performed on a directory
    /// basis, the size field will contain the maximum number of bytes (which may be rounded to
    /// the nearest disk block allocation unit) which the directory may hold. A size field of zero
    /// indicates no such limiting. Systems which do not support limiting in this manner should
    /// ignore the size field.
    DIRTYPE = 5,
    /// This specifies a FIFO special file. Note that the archiving of a FIFO file archives the
    /// existence of this file and not its contents.
    FIFOTYPE = 6,
    /// This specifies a contiguous file, which is the same as a normal file except that, in
    /// operating systems which support it, all its space is allocated contiguously on the disk.
    /// Operating systems which do not allow contiguous allocation should silently treat this type
    /// as a normal file.
    CONTTYPE = 7,
    /// Extended header referring to the next file in the archive
    XHDTYPE = b'x',
    /// Global extended header
    XGLTYPE = b'g',
}

bitflags::bitflags! {
    /// UNIX file permissions on octal format.
    pub struct ModeFlags: u64 {
        /// Set UID on execution.
        const SetUID = 0o4000;
        /// Set GID on execution.
        const SetGID = 0o2000;
        /// Reserved.
        const TSVTX = 0o1000;
        /// Owner read.
        const OwnerRead = 0o400;
        /// Owner write.
        const OwnerWrite = 0o200;
        /// Owner execute.
        const OwnerExec = 0o100;
        /// Group read.
        const GroupRead = 0o040;
        /// Group write.
        const GroupWrite = 0o020;
        /// Group execute.
        const GroupExec = 0o010;
        /// Others read.
        const OthersRead = 0o004;
        /// Others read.
        const OthersWrite = 0o002;
        /// Others execute.
        const OthersExec = 0o001;
    }
}

#[cfg(test)]
mod tests {
    use crate::header::{PosixHeader, StaticCString, TypeFlag};
    use crate::BLOCKSIZE;
    use std::mem::size_of;

    fn bytes_to_archive(bytes: &[u8]) -> PosixHeader {
        let hdr = bytes.as_ptr() as *const PosixHeader;
        unsafe { core::ptr::read(hdr) }
    }

    #[test]
    fn test_display_header() {
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_default.tar"));
        println!("{:#?}'", archive);
    }

    #[test]
    fn test_show_tar_header_magics() {
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_default.tar"));
        println!(
            "default: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_gnu.tar"));
        println!(
            "gnu: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_oldgnu.tar"));
        println!(
            "oldgnu: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_pax.tar"));
        println!(
            "pax: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_posix.tar"));
        println!(
            "posix: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_ustar.tar"));
        println!(
            "ustar: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_v7.tar"));
        println!(
            "v7: magic='{:?}', version='{:?}'",
            archive.magic, archive.version
        );
    }

    #[test]
    fn test_parse_tar_header_filename() {
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_default.tar"));
        assert_eq!(
            archive.typeflag,
            TypeFlag::REGTYPE,
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt");

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_gnu.tar"));
        assert_eq!(
            archive.typeflag,
            TypeFlag::REGTYPE,
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt");

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_oldgnu.tar"));
        assert_eq!(
            archive.typeflag,
            TypeFlag::REGTYPE,
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt");

        /* UNSUPPORTED YET. Uses extensions..
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_pax.tar"));
        assert_eq!(archive.typeflag, TypeFlag::REGTYPE, "the first entry is a regular file!");
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt"); */

        /* UNSUPPORTED YET. Uses extensions.
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_posix.tar"));
        unsupported extension XHDTYPE assert_eq!(archive.typeflag, TypeFlag::REGTYPE, "the first entry is a regular file!");
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt"); */

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_ustar.tar"));
        assert_eq!(
            archive.typeflag,
            TypeFlag::REGTYPE,
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt");

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_v7.tar"));
        // ARegType: legacy
        assert_eq!(
            archive.typeflag,
            TypeFlag::AREGTYPE,
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_string().as_str(), "bye_world_513b.txt");
    }

    #[test]
    fn test_size() {
        assert_eq!(BLOCKSIZE, size_of::<PosixHeader>());
    }

    #[test]
    fn test_static_str() {
        let str = StaticCString::new(*b"0000633\0");
        assert_eq!(str.len(), 7);
        assert_eq!(str.as_string().as_str(), "0000633");
    }
}
