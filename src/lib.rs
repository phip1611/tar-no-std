// SPDX-License-Identifier: MIT

//! Library to read Tar archives (tarballs) in `no_std` environments with zero
//! allocations.
//!
//! If you have a standard environment and need full feature support, I
//! recommend the use of <https://crates.io/crates/tar> instead.
//!
//! _Due to historical reasons, there are several formats of Tar archives. All
//! of them are based on the same principles, but have some subtle differences
//! that often make them incompatible with each other._
//! [(reference)](https://www.gnu.org/software/tar/manual/html_section/Formats.html)
//!
//! ## TL;DR
//!
//! Most ordinary Tar archives containing regular files will work.
//!
//! ## Limitations
//!
//! Archives created by a typical GNU tar, bsdtar (macOS), busybox, or Python
//! invocation work. This includes basic Tar, ustar, GNU, and PAX
//! [archives](https://www.gnu.org/software/tar/manual/html_section/Formats.html).
//! GNU long names and PAX paths of up to 256 bytes are applied to the
//! filenames. Other PAX records, such as high-precision timestamps, are
//! skipped.
//!
//! Archives that rely on unsupported extensions are rejected. These are GNU
//! sparse files, and PAX sizes that differ from the regular header, which GNU
//! tar writes for files larger than 8GiB. Other vendor entries, such as GNU
//! incremental dumps or volume labels, are skipped. The maximum supported
//! filename length is 256 characters excluding the NULL-byte, and the maximum
//! supported file size is 8GiB. Directories, links, and other special entries
//! are skipped; iteration yields only regular files, preserving directory paths
//! encoded in their names.
//!
//! ## Use Case
//!
//! This library is useful, if you write a kernel or a similar low-level
//! application, which needs "a bunch of files" from an archive (like an "init
//! ramdisk"). The Tar file could for example come as a Multiboot2 boot module
//! provided by the bootloader.
//!
//! ## Example
//!
//! ```rust
//! use tar_no_std::TarArchiveRef;
//!
//! // For example, an init ramdisk that the bootloader loaded into memory.
//! let archive = include_bytes!("../tests/gnu_tar_default.tar");
//! let archive = TarArchiveRef::new(archive).expect("archive should be valid");
//!
//! // List all files, without allocating.
//! for entry in archive.entries() {
//!     let name = entry.filename();
//!     println!("{} ({} bytes)", name.as_str().unwrap_or("?"), entry.size());
//! }
//!
//! // Find a file by its name and read it.
//! let file = archive
//!     .entries()
//!     .find(|entry| entry.filename().as_str() == Ok("hello_world.txt"))
//!     .expect("archive should contain the file");
//! assert_eq!(file.data_as_str(), Ok("Hello World\n"));
//! ```
//!
//! ## Streaming
//!
//! Archives that do not fit into memory can be read block by block. We provide
//! [`TarStreamReader`], which pulls the blocks itself, and [`TarStreamParser`],
//! to which you pass the blocks one by one.
//!
//! [`TarStreamReader`] pulls 512-byte blocks from a [`BlockSource`], which
//! can be a closure or a type that reads from a file, a flash device, or a
//! network stream. It validates every header like [`TarArchiveRef::new`] does
//! and, like [`TarArchiveRef::entries`], only reports regular files. Payload
//! that is not read is skipped.
//!
//! ```rust
//! use std::io::{ErrorKind, Read};
//! use tar_no_std::TarStreamReader;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Stands in for a file that does not fit into memory.
//!     let mut file: &[u8] = include_bytes!("../tests/gnu_tar_default.tar");
//!     let mut reader = TarStreamReader::new(|block: &mut [u8; 512]| {
//!         match file.read_exact(block) {
//!             Ok(()) => Ok(true),
//!             Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(false),
//!             Err(e) => Err(e),
//!         }
//!     });
//!
//!     // Copy each file in small chunks, for example to a flash device.
//!     let mut chunk = [0; 64];
//!     while let Some(mut entry) = reader.next_entry()? {
//!         let name = entry.filename();
//!         println!("{} ({} bytes)", name.as_str()?, entry.size());
//!         loop {
//!             let n = entry.read_payload(&mut chunk)?;
//!             if n == 0 {
//!                 break;
//!             }
//!             // Write `chunk[..n]` to the destination.
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! If the blocks are pushed to you instead, for example by an interrupt, a DMA
//! callback, or a network stack, pass each block to [`TarStreamParser`] as it
//! arrives. It validates the archive the same way and reports the header of
//! each regular file, its payload bytes, and the end of the archive.
//!
//! ```rust
//! use tar_no_std::{StreamEvent, TarStreamParser};
//!
//! # fn main() -> Result<(), tar_no_std::CorruptDataError> {
//! # let archive = include_bytes!("../tests/gnu_tar_default.tar");
//! # let blocks = archive.chunks_exact(512).map(|b| b.try_into().unwrap());
//! let mut parser = TarStreamParser::new();
//! // For example, blocks that a network stack delivers one at a time.
//! for block in blocks {
//!     match parser.parse_block(block)? {
//!         Some(StreamEvent::Entry { filename, size, .. }) => {
//!             println!("{} ({size} bytes)", filename.as_str().unwrap_or("?"));
//!         }
//!         Some(StreamEvent::Data { data, .. }) => {
//!             // Write `data` to the destination.
//!             println!("  {} bytes", data.len());
//!         }
//!         Some(StreamEvent::End) | None => {}
//!     }
//! }
//! // Once the input ended, check that the archive was complete.
//! parser.finish()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Cargo Features
//!
//! This crate allows the usage of the additional Cargo build time feature
//! `alloc`. When this is active, the crate also provides the type `TarArchive`,
//! which owns the data on the heap.
//!
//! ## Compression (`tar.gz`)
//!
//! If your Tar file is compressed, e.g. by `.tar.gz`/`gzip`, you need to
//! uncompress the bytes first (e.g. by a *gzip* library). Afterwards, this
//! crate can read the Tar archive format from the uncompressed bytes.
//!
//! ## MSRV
//!
//! The MSRV is 1.85.0 stable.

#![cfg_attr(not(test), no_std)]
#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::absolute_paths,
    clippy::must_use_candidate,
    clippy::undocumented_unsafe_blocks
)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

#[cfg_attr(test, macro_use)]
#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

/// Size of a Tar block in bytes.
///
/// A Tar archive is a sequence of such blocks, each holding either a header or
/// payload.
pub const BLOCKSIZE: usize = 512;
/// Maximum filename length of the base Tar format including the terminating
/// NULL-byte.
const NAME_LEN: usize = 100;
/// Maximum long filename length of the base Tar format including the prefix.
const POSIX_1003_MAX_FILENAME_LEN: usize = 256;
/// Maximum payload size of a GNU long name entry that this crate supports.
///
/// The format has no limit, but this crate stores the name in a buffer of
/// [`POSIX_1003_MAX_FILENAME_LEN`] bytes, as it does not allocate. The payload
/// is the name and its terminating NULL-byte.
const MAX_LONG_NAME_PAYLOAD: usize = POSIX_1003_MAX_FILENAME_LEN + 1;
/// Maximum length of the prefix in Posix tar format.
const PREFIX_LEN: usize = 155;
/// Offset of the type flag in a header block.
///
/// Tests overwrite it to create entries of other types.
#[cfg(test)]
const TYPEFLAG_OFFSET: usize = core::mem::offset_of!(PosixHeader, typeflag);

mod archive;
mod header;
mod pax;
mod stream;
mod stream_reader;
mod tar_format_types;

pub use archive::*;
pub use header::*;
pub use stream::*;
pub use stream_reader::*;
pub use tar_format_types::{TarFormatOctal, TarFormatString};
