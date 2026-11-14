// SPDX-License-Identifier: MIT

//! Reads a file from an archive in memory, like a kernel that reads its init
//! ramdisk.

use tar_no_std::TarArchiveRef;

fn main() {
    // Optional: shows the log messages of the crate, such as skipped entries.
    unsafe {
        std::env::set_var("RUST_LOG", "trace");
        std::env::set_var("RUST_LOG_STYLE", "always");
    }
    env_logger::init();

    // This also works in no_std environments, except for the println!.
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive = TarArchiveRef::new(archive).expect("archive should be valid");

    for entry in archive.entries() {
        let name = entry.filename();
        println!("{} ({} bytes)", name.as_str().unwrap_or("?"), entry.size());
    }

    let file = archive
        .entries()
        .find(|entry| entry.filename().as_str() == Ok("hello_world.txt"))
        .expect("archive should contain the file");
    print!("{}", file.data_as_str().expect("file should be UTF-8"));
}
