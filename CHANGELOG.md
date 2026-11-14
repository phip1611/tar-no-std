# Unreleased

- Added cargo-fuzz infrastructure for archive parsing.
- Added structure-aware fuzzing of checksum-valid Tar archives.
- `PosixHeader::mtime` is now a `TarFormatOctal<12>` instead of a
  `TarFormatDecimal<12>`. The field is octal in the Tar format, so it was
  previously parsed to a wrong value.
- Removed `TarFormatDecimal`, which is no longer used by any header field.
- `TarFormatNumber` is no longer public. It was only used inside
  `TarFormatOctal`.
- Added `TarStreamReader` to read archives block by block from a
  `BlockSource` without holding them in memory. Its errors are reported as
  `StreamError`.
- Added `TarStreamParser` for archives whose blocks are pushed to the caller,
  for example by an interrupt or a network stack. It reports each block as a
  `StreamEvent`.
- `TarArchiveRef::new` and `TarArchive::new` now accept an empty archive that
  only consists of the two terminating zero blocks. `MIN_BLOCK_COUNT` and
  `CorruptDataError::TooShort` were removed: a single block is now reported as
  `MissingTerminator` or as an invalid header, like by `TarStreamParser`.
- `TarArchive` now implements `TryFrom<Box<[u8]>>` instead of
  `From<Box<[u8]>>`, which panicked for invalid archives.
- Skipped entries, such as directories, are now logged at debug level instead
  of warn level, because skipping them is the expected behavior.
- Contiguous files (type flag `7`) are now reported as regular files instead
  of being skipped, as the Tar spec requires.
- `ArchiveEntry::posix_header` now returns a reference that borrows the
  archive instead of the entry, like `ArchiveEntry::data`.
- Added `TarFormatString::as_bytes` to read strings that are not valid UTF-8,
  such as Latin-1 filenames.
- Numeric header fields with leading spaces, as written by some old Tar
  implementations, are now accepted.
- Regular files whose name ends with a slash are now skipped as directories,
  like GNU tar does. Old Tar versions wrote directories this way.
- Added support for GNU long names (type flag `L`) of up to 256 bytes, which
  GNU tar writes by default for paths longer than 100 characters. Such
  archives were rejected before. Longer names are rejected with the new
  `CorruptDataError::FilenameTooLong`. GNU long link names (type flag `K`) are
  skipped. `StreamEvent::Entry` has a new `filename` field that includes the
  long name.
- `BLOCKSIZE` is now public, for example to size the buffers of a
  `BlockSource`.
- Added `PosixHeader::filename`. It returns the filename including the ustar
  prefix, like `ArchiveEntry::filename`.

# v0.5.0 (2026-08-13)

- Removed the incorrect `ExactSizeIterator` implementation for
  `ArchiveEntryIterator`.
- Numeric fields with invalid UTF-8 bytes now fail parsing instead of being
  read as zero.
- Added limited support for reading POSIX PAX archives that use extended
  records only for optional metadata, such as high-precision timestamps. PAX
  metadata is skipped rather than applied, so filenames and sizes must remain
  available in the regular file headers.
- Documentation improvements
- `TarArchiveRef::new` and `TarArchive::new` now reject invalid headers,
  checksums, payload sizes, and missing archive termination.
- `CorruptDataError` now identifies the failed archive validation invariant.
  The `struct` is now an `enum`.
- `ArchiveHeaderIterator::new` is now private. Use `TarArchive::headers` or
  `TarArchiveRef::headers` to iterate over validated archive headers.

# v0.4.2 (2025-08-25)

- documentation improvements

# v0.4.1 (2025-08-08)

- `ModeError` now also implements the `Error` trait

# v0.4.0 (2025-08-08)
-
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
