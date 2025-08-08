# Unreleased

# v0.4.0 (2025-08-08)
- MSRV is now `1.85.0`
- Rust edition 2024
- Removed feature `unstable`: `core::error::Error` is now implemented
  unconditionally for the error types.

# v0.3.5 (2025-08-08)

- Increased lifetime of `TarArchiveRef::entries`
- Dropped dependency on `memchr`

# v0.3.4 (2025-05-13)

- Fixed a bug when data fills an entire block

# v0.3.3 (2025-03-20)

- Added `ArchiveEntry::posix_header()` to get metadata for an entry

# v0.3.2 (2024-08-02)

- `TarArchive::entries` is now `#[must_use]`

# v0.3.1 (2024-05-03)

- More sanity checks with malformed Tar archives.

# v0.3.0 (2024-05-03)

- MSRV is now 1.76 stable
- added support for more Tar archives
    - 256 character long filename support (prefix + name)
    - add support for space terminated numbers
    - non-null terminated names
    - iterate over directories: read regular files from directories
    - more info: <https://github.com/phip1611/tar-no-std/pull/10>
- `TarArchive[Ref]::new` now returns a result
- added `unstable` feature with enhanced functionality for `nightly` compilers
    - error types implement `core::error::Error`
- various bug fixes and code improvements
- better error reporting / less panics

Special thanks to the following external contributors or helpers:

- https://github.com/thenhnn: provide me with a bunch of Tar archives coming
  from a fuzzer
- https://github.com/schnoberts1 implemented 256 character long filenames (ustar
  Tar format)

# v0.2.0 (2023-04-11)

- MSRV is 1.60.0
- bitflags bump: 1.x -> 2.x
- few internal code improvements (less possible panics)
- `Mode::to_flags` now returns a Result
- Feature `all` was removed. Use `alloc` instead.
