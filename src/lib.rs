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
//! Library to read Tar archives (by GNU Tar) in `no_std` contexts with zero allocations.
//! If you have a standard environment and need full feature support, I recommend the use of
//! <https://crates.io/crates/tar> instead.
//!
//! The crate is simple and only supports reading of "basic" archives, therefore no extensions, such
//! as GNU Longname. The maximum supported file name length is 100 characters including the NULL-byte.
//! The maximum supported file size is 8GiB. Also, directories are not supported yet but only flat
//! collections of files.
//!
//! This library is useful, if you write a kernel or a similar low-level application, which needs
//! "a bunch of files" from an archive ("init ram disk"). The Tar file could for example come
//! as a Multiboot2 boot module provided by the bootloader.
//!
//! This crate focuses on extracting files from uncompressed Tar archives created with default options by **GNU Tar**.
//! GNU Extensions such as sparse files, incremental archives, and long filename extension are not supported yet.
//! [This link](https://www.gnu.org/software/tar/manual/html_section/Formats.html) gives a good overview over possible
//! archive formats and their limitations.

#![cfg_attr(not(test), no_std)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_doc_code_examples)]
#![deny(clippy::all)]
#![deny(clippy::missing_const_for_fn)]
#![deny(missing_debug_implementations)]

#[cfg_attr(test, macro_use)]
#[cfg(test)]
extern crate std;

/// Each Archive Entry (either Header or Data Block) is a block of 512 bytes.
const BLOCKSIZE: usize = 512;

mod archive;
mod header;

pub use archive::*;
pub use header::*;
