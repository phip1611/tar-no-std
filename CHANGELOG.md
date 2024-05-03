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

# v0.2.0 (2023-04-11)
- MSRV is 1.60.0
- bitflags bump: 1.x -> 2.x
- few internal code improvements (less possible panics)
- `Mode::to_flags` now returns a Result
- Feature `all` was removed. Use `alloc` instead.
