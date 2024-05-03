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
//! # `tar-no-std` - Parse Tar Archives (Tarballs)
//!
//! _Due to historical reasons, there are several formats of Tar archives. All of
//! them are based on the same principles, but have some subtle differences that
//! often make them incompatible with each other._ [(reference)](https://www.gnu.org/software/tar/manual/html_section/Formats.html)
//!
//! Library to read Tar archives in `no_std` environments with zero allocations. If
//! you have a standard environment and need full feature support, I recommend the
//! use of <https://crates.io/crates/tar> instead.
//!
//! ## TL;DR
//!
//! Look at the [`TarArchiveRef`] type.
//!
//! ## Limitations
//!
//! This crate is simple and focuses on reading files and their content from a Tar
//! archive. Historic basic Tar and ustar [formats](https://www.gnu.org/software/tar/manual/html_section/Formats.html)
//! are supported. Other formats may work, but likely without all supported
//! features. GNU Extensions such as sparse files, incremental archives, and
//! long filename extension are not supported.
//!
//! The maximum supported file name length is 256 characters excluding the
//! NULL-byte (using the Tar name/prefix longname implementation of ustar). The
//! maximum supported file size is 8GiB. Directories are supported, but only regular
//! fields are yielded in iteration. The path is reflected in their file name.
//!
//! ## Use Case
//!
//! This library is useful, if you write a kernel or a similar low-level
//! application, which needs "a bunch of files" from an archive (like an
//! "init ramdisk"). The Tar file could for example come as a Multiboot2 boot module
//! provided by the bootloader.
//!
//! ## Example
//!
//! ```rust
//! use tar_no_std::TarArchiveRef;
//!
//! // init a logger (optional)
//! std::env::set_var("RUST_LOG", "trace");
//! env_logger::init();
//!
//! // also works in no_std environment (except the println!, of course)
//! let archive = include_bytes!("../tests/gnu_tar_default.tar");
//! let archive = TarArchiveRef::new(archive).unwrap();
//! // Vec needs an allocator of course, but the library itself doesn't need one
//! let entries = archive.entries().collect::<Vec<_>>();
//! println!("{:#?}", entries);
//! ```
//!
//! ## Cargo Feature
//!
//! This crate allows the usage of the additional Cargo build time feature `alloc`.
//! When this is active, the crate also provides the type `TarArchive`, which owns
//! the data on the heap. The `unstable` feature provides additional convenience
//! only available on the nightly channel.
//!
//! ## Compression (`tar.gz`)
//!
//! If your Tar file is compressed, e.g. by `.tar.gz`/`gzip`, you need to uncompress
//! the bytes first (e.g. by a *gzip* library). Afterwards, this crate can read the
//! Tar archive format from the uncompressed bytes.
//!
//! ## MSRV
//!
//! The MSRV is 1.76.0 stable.

#![cfg_attr(feature = "unstable", feature(error_in_core))]
#![cfg_attr(not(test), no_std)]
#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    // clippy::restriction,
    // clippy::pedantic
)]
// now allow a few rules which are denied by the above statement
// --> they are ridiculous and not necessary
#![allow(
    clippy::suboptimal_flops,
    clippy::redundant_pub_crate,
    clippy::fallible_impl_from
)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]

#[cfg_attr(test, macro_use)]
#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

/// Each Archive Entry (either Header or Data Block) is a block of 512 bytes.
const BLOCKSIZE: usize = 512;
/// Maximum filename length of the base Tar format including the terminating NULL-byte.
const NAME_LEN: usize = 100;
/// Maximum long filename length of the base Tar format including the prefix
const POSIX_1003_MAX_FILENAME_LEN: usize = 256;
/// Maximum length of the prefix in Posix tar format
const PREFIX_LEN: usize = 155;

mod archive;
mod header;
mod tar_format_types;

pub use archive::*;
pub use header::*;
pub use tar_format_types::*;
