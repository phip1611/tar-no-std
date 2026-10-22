// SPDX-License-Identifier: MIT

use tar_no_std::TarArchiveRef;

fn main() {
    // log: not mandatory
    unsafe {
        std::env::set_var("RUST_LOG", "trace");
        std::env::set_var("RUST_LOG_STYLE", "always");
    }
    env_logger::init();

    // also works in no_std environment (except the println!, of course)
    let archive = include_bytes!("../tests/gnu_tar_default.tar");
    let archive = TarArchiveRef::new(archive).unwrap();
    // Vec needs an allocator of course, but the library itself doesn't need one
    let entries = archive.entries().collect::<Vec<_>>();
    println!("{:#?}", entries);
    println!("content of last file:");
    println!(
        "{:#?}",
        entries[2].data_as_str().expect("Should be valid UTF-8")
    );
}
