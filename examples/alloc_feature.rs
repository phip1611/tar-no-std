// SPDX-License-Identifier: MIT

//! Reads an archive that is owned on the heap, for example the output of a
//! gzip decoder.

use tar_no_std::TarArchive;

fn main() {
    // Optional: shows the log messages of the crate, such as skipped entries.
    unsafe {
        std::env::set_var("RUST_LOG", "trace");
        std::env::set_var("RUST_LOG_STYLE", "always");
    }
    env_logger::init();

    // Stands in for the decompressed bytes of a .tar.gz file.
    let data = include_bytes!("../tests/gnu_tar_default.tar").to_vec();
    let archive = TarArchive::try_from(data.into_boxed_slice()).expect("archive should be valid");

    for entry in archive.entries() {
        let name = entry.filename();
        println!("{} ({} bytes)", name.as_str().unwrap_or("?"), entry.size());
    }
}
