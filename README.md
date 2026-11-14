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

Archives created by a typical GNU tar, bsdtar (macOS), busybox, or Python
invocation work. This includes basic Tar, ustar, GNU, and PAX
[archives](https://www.gnu.org/software/tar/manual/html_section/Formats.html).
GNU long names and PAX paths of up to 256 bytes are applied to the filenames.
Other PAX records, such as high-precision timestamps, are skipped.

Archives that rely on unsupported extensions are rejected. These are GNU sparse
files, and PAX sizes that differ from the regular header, which GNU tar writes
for files larger than 8GiB. Other vendor entries, such as GNU incremental dumps
or volume labels, are skipped. The maximum supported filename length is 256
characters excluding the NULL-byte, and the maximum supported file size is 8GiB.
Directories, links, and other special entries are skipped; iteration yields only
regular files, preserving directory paths encoded in their names.

## Use Case

This library is useful, if you write a kernel or a similar low-level
application, which needs "a bunch of files" from an archive (like an "init
ramdisk"). The Tar file could for example come as a Multiboot2 boot module
provided by the bootloader.

## Examples

Read a file from an archive in memory:

```rust
use tar_no_std::TarArchiveRef;

// For example, an init ramdisk that the bootloader loaded into memory.
let archive = include_bytes!("../tests/gnu_tar_default.tar");
let archive = TarArchiveRef::new(archive).expect("archive should be valid");

// List all files, without allocating.
for entry in archive.entries() {
    let name = entry.filename();
    println!("{} ({} bytes)", name.as_str().unwrap_or("?"), entry.size());
}

// Find a file by its name and read it.
let file = archive
    .entries()
    .find(|entry| entry.filename().as_str() == Ok("hello_world.txt"))
    .expect("archive should contain the file");
assert_eq!(file.data_as_str(), Ok("Hello World\n"));
```

Read an archive that does not fit into memory, block by block:

```rust
use std::io::{ErrorKind, Read};
use tar_no_std::TarStreamReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Stands in for a file that does not fit into memory.
    let mut file: &[u8] = include_bytes!("../tests/gnu_tar_default.tar");
    let mut reader = TarStreamReader::new(|block: &mut [u8; 512]| {
        match file.read_exact(block) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(e),
        }
    });

    // Copy each file in small chunks, for example to a flash device.
    let mut chunk = [0; 64];
    while let Some(mut entry) = reader.next_entry()? {
        let name = entry.filename();
        println!("{} ({} bytes)", name.as_str()?, entry.size());
        loop {
            let n = entry.read_payload(&mut chunk)?;
            if n == 0 {
                break;
            }
            // Write `chunk[..n]` to the destination.
        }
    }
    Ok(())
}
```

## Documentation

See the [documentation on docs.rs](https://docs.rs/tar-no-std) for more
examples, such as for blocks that are pushed to you, Cargo features, compressed
archives, and the MSRV.

## Fuzzing

The `parse_archive` fuzz target validates arbitrary bytes. To use the existing
test archives as seeds, run:

```shell
mkdir -p fuzz/corpus/parse_archive
cargo +nightly fuzz run parse_archive fuzz/corpus/parse_archive tests \
  -- -max_total_time=60
```

The `parse_valid_archive` target generates structurally valid archives to
exercise parsing beyond checksum validation:

```shell
cargo +nightly fuzz run parse_valid_archive -- -max_total_time=60
```

Generated corpus entries, artifacts, coverage data, and build output below
`fuzz/` are ignored by Git. cargo-fuzz requires a nightly Rust toolchain.

### TODO

- Add coverage reporting to identify remaining parser blind spots.
- Fuzz the feature-gated, owning `TarArchive` API.
