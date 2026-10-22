// SPDX-License-Identifier: MIT

//! Module for `TarStreamParser`, which parses a Tar archive one block at a
//! time, without requiring the whole archive in memory.

use crate::POSIX_1003_MAX_FILENAME_LEN;
use crate::header::{PosixHeader, TypeFlag};
use crate::tar_format_types::TarFormatString;

/// Header of a regular file in the archive, as reported by
/// `TarStreamParser`.
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

/// Event returned by `TarStreamParser::parse_block`.
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
