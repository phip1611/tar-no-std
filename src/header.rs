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
//! TAR header definition taken from <https://www.gnu.org/software/tar/manual/html_node/Standard.html>.
//! A Tar-archive is a collection of 512-byte sized blocks. Unfortunately there are several
//! TAR-like archive specifications. An Overview can be found here:
//! <https://www.gnu.org/software/tar/manual/html_node/Formats.html#Formats>
//!
//! This library focuses on extracting files from the GNU Tar format.

#![allow(non_upper_case_globals)]

use crate::{TarFormatDecimal, TarFormatOctal, TarFormatString, BLOCKSIZE, NAME_LEN, PREFIX_LEN};
use core::fmt::{Debug, Display, Formatter};
use core::num::ParseIntError;

/// Errors that may happen when parsing the [`ModeFlags`].
#[derive(Debug)]
pub enum ModeError {
    ParseInt(ParseIntError),
    IllegalMode,
}

/// Wrapper around the UNIX file permissions given in octal ASCII.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Mode(TarFormatOctal<8>);

impl Mode {
    /// Parses the [`ModeFlags`] from the mode string.
    pub fn to_flags(self) -> Result<ModeFlags, ModeError> {
        let bits = self.0.as_number::<u64>().map_err(ModeError::ParseInt)?;
        ModeFlags::from_bits(bits).ok_or(ModeError::IllegalMode)
    }
}

impl Debug for Mode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.to_flags(), f)
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C, packed)]
pub struct PosixHeader {
    pub name: TarFormatString<NAME_LEN>,
    pub mode: Mode,
    pub uid: TarFormatOctal<8>,
    pub gid: TarFormatOctal<8>,
    // confusing; size is stored as ASCII string
    pub size: TarFormatOctal<12>,
    pub mtime: TarFormatDecimal<12>,
    pub cksum: TarFormatOctal<8>,
    pub typeflag: TypeFlagRaw,
    /// Name. There is always a null byte, therefore
    /// the max len is 99.
    pub linkname: TarFormatString<NAME_LEN>,
    pub magic: TarFormatString<6>,
    pub version: TarFormatString<2>,
    /// Username. There is always a null byte, therefore
    /// the max len is N-1.
    pub uname: TarFormatString<32>,
    /// Groupname. There is always a null byte, therefore
    /// the max len is N-1.
    pub gname: TarFormatString<32>,
    pub dev_major: TarFormatOctal<8>,
    pub dev_minor: TarFormatOctal<8>,
    pub prefix: TarFormatString<PREFIX_LEN>,
    // padding => to BLOCKSIZE bytes
    pub _pad: [u8; 12],
}

impl PosixHeader {
    /// Returns the number of blocks that are required to read the whole file
    /// content. Returns an error, if the file size can't be parsed from the
    /// header.
    pub fn payload_block_count(&self) -> Result<usize, ParseIntError> {
        let parsed_size = self.size.as_number::<usize>()?;
        Ok(parsed_size.div_ceil(BLOCKSIZE))
    }

    /// A Tar archive is terminated, if an end-of-archive entry, which consists
    /// of two 512 blocks of zero bytes, is found.
    pub fn is_zero_block(&self) -> bool {
        let ptr = self as *const Self as *const u8;
        let self_bytes = unsafe { core::slice::from_raw_parts(ptr, BLOCKSIZE) };
        self_bytes.iter().filter(|x| **x == 0).count() == BLOCKSIZE
    }
}

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
pub struct InvalidTypeFlagError(u8);

impl Display for InvalidTypeFlagError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:x} is not a valid TypeFlag", self.0))
    }
}

#[cfg(feature = "unstable")]
impl core::error::Error for InvalidTypeFlagError {}

#[derive(Copy, Clone, PartialOrd, PartialEq, Eq)]
pub struct TypeFlagRaw(u8);

impl TypeFlagRaw {
    /// Tries to parse the underlying value as [`TypeFlag`]. This fails if the
    /// Tar file is corrupt and the type is invalid.
    pub fn try_to_type_flag(self) -> Result<TypeFlag, InvalidTypeFlagError> {
        TypeFlag::try_from(self)
    }
}

impl Debug for TypeFlagRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.try_to_type_flag(), f)
    }
}

/// Describes the kind of payload, that follows after a
/// [`PosixHeader`]. The properties of this payload are
/// described inside the header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
    LINK = b'1',
    /// This represents a symbolic link to another file. The linked-to name is specified in the
    /// linkname field with a trailing null.
    SYMTYPE = b'2',
    /// Represents character special files and block special files respectively. In this case the
    /// devmajor and devminor fields will contain the major and minor device numbers respectively.
    /// Operating systems may map the device specifications to their own local specification, or
    /// may ignore the entry.
    CHRTYPE = b'3',
    /// Represents character special files and block special files respectively. In this case the
    /// devmajor and devminor fields will contain the major and minor device numbers respectively.
    /// Operating systems may map the device specifications to their own local specification, or
    /// may ignore the entry.
    BLKTYPE = b'4',
    /// This flag specifies a directory or sub-directory. The directory name in the name field
    /// should end with a slash. On systems where disk allocation is performed on a directory
    /// basis, the size field will contain the maximum number of bytes (which may be rounded to
    /// the nearest disk block allocation unit) which the directory may hold. A size field of zero
    /// indicates no such limiting. Systems which do not support limiting in this manner should
    /// ignore the size field.
    DIRTYPE = b'5',
    /// This specifies a FIFO special file. Note that the archiving of a FIFO file archives the
    /// existence of this file and not its contents.
    FIFOTYPE = b'6',
    /// This specifies a contiguous file, which is the same as a normal file except that, in
    /// operating systems which support it, all its space is allocated contiguously on the disk.
    /// Operating systems which do not allow contiguous allocation should silently treat this type
    /// as a normal file.
    CONTTYPE = b'7',
    /// Extended header referring to the next file in the archive
    XHDTYPE = b'x',
    /// Global extended header
    XGLTYPE = b'g',
}

impl TypeFlag {
    /// Whether we have a regular file.
    pub fn is_regular_file(self) -> bool {
        // Equivalent. See spec.
        self == Self::AREGTYPE || self == Self::REGTYPE
    }
}

impl TryFrom<TypeFlagRaw> for TypeFlag {
    type Error = InvalidTypeFlagError;

    fn try_from(value: TypeFlagRaw) -> Result<Self, Self::Error> {
        match value.0 {
            b'0' => Ok(Self::REGTYPE),
            b'\0' => Ok(Self::AREGTYPE),
            b'1' => Ok(Self::LINK),
            b'2' => Ok(Self::SYMTYPE),
            b'3' => Ok(Self::CHRTYPE),
            b'4' => Ok(Self::BLKTYPE),
            b'5' => Ok(Self::DIRTYPE),
            b'6' => Ok(Self::FIFOTYPE),
            b'7' => Ok(Self::CONTTYPE),
            b'x' => Ok(Self::XHDTYPE),
            b'g' => Ok(Self::XGLTYPE),
            e => Err(InvalidTypeFlagError(e)),
        }
    }
}

bitflags::bitflags! {
    /// UNIX file permissions in octal format.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    use crate::header::{PosixHeader, TypeFlag};
    use crate::BLOCKSIZE;
    use std::mem::size_of;

    /// Returns the PosixHeader at the beginning of the Tar archive.
    fn bytes_to_archive(tar_archive_data: &[u8]) -> &PosixHeader {
        unsafe { (tar_archive_data.as_ptr() as *const PosixHeader).as_ref() }.unwrap()
    }

    #[test]
    fn test_display_header() {
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_default.tar"));
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));
        println!("{:#?}'", archive);
    }

    #[test]
    fn test_payload_block_count() {
        // first file is "bye_world_513b.txt" => we expect two data blocks
        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_default.tar"));
        assert_eq!(archive.payload_block_count(), Ok(2));
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
            archive.typeflag.try_to_type_flag(),
            Ok(TypeFlag::REGTYPE),
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_gnu.tar"));
        assert_eq!(
            archive.typeflag.try_to_type_flag(),
            Ok(TypeFlag::REGTYPE),
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_oldgnu.tar"));
        assert_eq!(
            archive.typeflag.try_to_type_flag(),
            Ok(TypeFlag::REGTYPE),
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));

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
            archive.typeflag.try_to_type_flag(),
            Ok(TypeFlag::REGTYPE),
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));

        let archive = bytes_to_archive(include_bytes!("../tests/gnu_tar_v7.tar"));
        // ARegType: legacy
        assert_eq!(
            archive.typeflag.try_to_type_flag(),
            Ok(TypeFlag::AREGTYPE),
            "the first entry is a regular file!"
        );
        assert_eq!(archive.name.as_str(), Ok("bye_world_513b.txt"));
    }

    #[test]
    fn test_size() {
        assert_eq!(BLOCKSIZE, size_of::<PosixHeader>());
    }
}
