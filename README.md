# `tar-no-std` - Parse Tar Archives (Tarballs)

_Due to historical reasons, there are several formats of Tar archives. All of
them are based on the same principles, but have some subtle differences that
often make them incompatible with each other._ [(reference)](https://www.gnu.org/software/tar/manual/html_section/Formats.html)

Library to read Tar archives in `no_std` environments with zero allocations. If
you have a standard environment and need full feature support, I recommend the
use of <https://crates.io/crates/tar> instead.

## Limitations

This crate is simple and focuses on reading files and their content from a Tar
archive. Historic basic Tar and ustar [formats](https://www.gnu.org/software/tar/manual/html_section/Formats.html)
are supported. Other formats may work, but likely without all supported
features. GNU Extensions such as sparse files, incremental archives, and long
filename extension are not supported.

The maximum supported file name length is 256 characters excluding the
NULL-byte (using the Tar name/prefix longname implementation of ustar). The
maximum supported file size is 8GiB. Directories are supported, but only regular
fields are yielded in iteration. The path is reflected in their file name.

## Use Case

This library is useful, if you write a kernel or a similar low-level
application, which needs "a bunch of files" from an archive (like an
"init ramdisk"). The Tar file could for example come as a Multiboot2 boot module
provided by the bootloader.

## Example

```rust
use tar_no_std::TarArchiveRef;

fn main() {
    // init a logger (optional)
    std::env::set_var("RUST_LOG", "trace");
    env_logger::init();

    // also works in no_std environment (except the println!, of course)
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive = TarArchiveRef::new(archive).unwrap();
    // Vec needs an allocator of course, but the library itself doesn't need one
    let entries = archive.entries().collect::<Vec<_>>();
    println!("{:#?}", entries);
}
```

## Cargo Feature

This crate allows the usage of the additional Cargo build time feature `alloc`.
When this is active, the crate also provides the type `TarArchive`, which owns
the data on the heap. The `unstable` feature provides additional convenience
only available on the nightly channel.

## Compression (`tar.gz`)

If your Tar file is compressed, e.g. by `.tar.gz`/`gzip`, you need to uncompress
the bytes first (e.g. by a *gzip* library). Afterwards, this crate can read the
Tar archive format from the uncompressed bytes.

## MSRV

The MSRV is 1.76.0 stable.
