# `tar-no-std` - Parse Tar Archives (Tarballs)

_Due to historical reasons, there are several formats of tar archives. All of them are based on the same principles,
but have some subtle differences that often make them incompatible with each other._ [[0]]

Library to read Tar archives (by GNU Tar) in `no_std` contexts with zero allocations. If you have a standard
environment and need full feature support, I recommend the use of <https://crates.io/crates/tar> instead.
The crate is simple and only supports reading of "basic" archives, therefore no extensions, such
as *GNU Longname*. The maximum supported file name length is 100 characters including the NULL-byte.
The maximum supported file size is 8GiB. Also, directories are not supported yet but only flat
collections of files.

This library is useful, if you write a kernel or a similar low-level application, which needs
"a bunch of files" from an archive ("init ramdisk"). The Tar file could for example come
as a Multiboot2 boot module provided by the bootloader.

This crate focuses on extracting files from uncompressed Tar archives created with default options by **GNU Tar**.
GNU Extensions such as sparse files, incremental archives, and long filename extension are not supported yet.
[This link](https://www.gnu.org/software/tar/manual/html_section/Formats.html) gives a good overview over possible
archive formats and their limitations.

## Example (without `alloc`-feature)
```rust
use tar_no_std::TarArchiveRef;

fn main() {
    // log: not mandatory
    std::env::set_var("RUST_LOG", "trace");
    env_logger::init();

    // also works in no_std environment (except the println!, of course)
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive = TarArchiveRef::new(archive);
    // Vec needs an allocator of course, but the library itself doesn't need one
    let entries = archive.entries().collect::<Vec<_>>();
    println!("{:#?}", entries);
    println!("content of last file:");
    println!("{:#?}", entries[2].data_as_str().expect("Invalid UTF-8") );
}
```

## Alloc Feature
This crate allows the additional Cargo build time feature `alloc`. When this is used, the crate
also provides the type `TarArchive`, which owns the data on the heap.

## Compression (`tar.gz`)
If your tar file is compressed, e.g. by `.tar.gz`/`gzip`, you need to uncompress the bytes first
(e.g. by a *gzip* library). Afterwards, this crate can read and write the Tar archive format from the bytes.

## MSRV
The MSRV is 1.51.0 stable.


[0]: https://www.gnu.org/software/tar/manual/html_section/Formats.html
