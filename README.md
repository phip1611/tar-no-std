# `tar-no-std` - Parse Tar Archives (Tarballs)

_Due to historical reasons, there are several formats of Tar archives. All of
them are based on the same principles, but have some subtle differences that
often make them incompatible with each other._ [(reference)](https://www.gnu.org/software/tar/manual/html_section/Formats.html)

Library to read Tar archives in `no_std` environments with zero allocations. If
you have a standard environment and need full feature support, I recommend the
use of <https://crates.io/crates/tar> instead.

## TL;DR

Most ordinary Tar archives containing regular files will work.

## Limitations

Archives created by a typical GNU tar or macOS `tar` invocation work when their
regular-file names and sizes fit in the regular Tar headers. This includes
basic Tar and ustar [archives](https://www.gnu.org/software/tar/manual/html_section/Formats.html),
as well as PAX archives that use extended records only for optional metadata
such as high-precision timestamps. PAX headers and their metadata are skipped;
the following regular-file headers provide the filenames and sizes.

Archives that rely on unsupported extensions do not work correctly. This
includes GNU long names, sparse files, incremental archives, and PAX-only paths
or file sizes. The maximum supported filename length is 256 characters
excluding the NULL-byte, and the maximum supported file size is 8GiB.
Directories, links, and other special entries are skipped; iteration yields only
regular files, preserving directory paths encoded in their names.

## Use Case

This library is useful, if you write a kernel or a similar low-level
application, which needs "a bunch of files" from an archive (like an
"init ramdisk"). The Tar file could for example come as a Multiboot2 boot module
provided by the bootloader.

## Example

```rust
use tar_no_std::TarArchiveRef;

fn main() {
    // also works in no_std environment (except the println!, of course)
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive = TarArchiveRef::new(archive).unwrap();
    // Vec needs an allocator of course, but the library itself doesn't need one
    let entries = archive.entries().collect::<Vec<_>>();
    println!("{:#?}", entries);
}
```

## Cargo Features

This crate allows the usage of the additional Cargo build time feature `alloc`.
When this is active, the crate also provides the type `TarArchive`, which owns
the data on the heap.

## Compression (`tar.gz`)

If your Tar file is compressed, e.g. by `.tar.gz`/`gzip`, you need to uncompress
the bytes first (e.g. by a *gzip* library). Afterwards, this crate can read the
Tar archive format from the uncompressed bytes.

## MSRV

The MSRV is 1.85.0 stable.

## Fuzzing

The `parse_archive` fuzz target validates arbitrary input and exercises the
public header and entry iterators for valid archives. To use the existing test
archives as seeds, run:

```shell
mkdir -p fuzz/corpus/parse_archive
cargo +nightly fuzz run parse_archive fuzz/corpus/parse_archive tests
```

Generated corpus entries, artifacts, coverage data, and build output below
`fuzz/` are ignored by Git. cargo-fuzz requires a nightly Rust toolchain.
