# `tar-no-std` - Parse Tar Archives (Tarballs)

_Due to historical reasons, there are several formats of Tar archives. All of
them are based on the same principles, but have some subtle differences that
often make them incompatible with each other._ [(reference)](https://www.gnu.org/software/tar/manual/html_section/Formats.html)

Library to read Tar archives in `no_std` environments with zero allocations. If
you have a standard environment and need full feature support, I recommend the
use of <https://crates.io/crates/tar> instead.

## Limitations

This crate focuses on reading regular files and their contents from historic
basic Tar and ustar [archives](https://www.gnu.org/software/tar/manual/html_section/Formats.html).
It can also read PAX archives that use extended records only for optional
metadata, such as high-precision timestamps. PAX metadata is skipped rather
than applied, so filenames and sizes must remain available in the regular file
headers.

Other formats may work when their regular file headers are compatible with the
supported formats. GNU extensions such as sparse files, incremental archives,
and GNU long names are not supported (yet).

The maximum supported file name length is 256 characters excluding the
NULL-byte (using the Tar name/prefix longname implementation of ustar). The
maximum supported file size is 8GiB. Directory, link, and other special entries
are skipped; iteration yields only regular files. Directory paths encoded in a
regular file's name are preserved.

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
