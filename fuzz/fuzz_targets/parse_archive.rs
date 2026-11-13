// SPDX-License-Identifier: MIT

#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;
use tar_no_std::TarArchiveRef;

mod exercise;

fuzz_target!(|data: &[u8]| {
    exercise::stream(data);

    let archive = match TarArchiveRef::new(data) {
        Ok(archive) => archive,
        Err(error) => {
            black_box(error);
            return;
        }
    };

    exercise::archive(&archive);
});
