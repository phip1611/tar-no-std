#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;
use tar_no_std::TarArchiveRef;

fuzz_target!(|data: &[u8]| {
    let Ok(archive) = TarArchiveRef::new(data) else {
        return;
    };

    for (_, header) in archive.headers() {
        let _ = black_box(header.name.as_str());
        let _ = black_box(header.mode.to_flags());
        let _ = black_box(header.uid.as_number::<u64>());
        let _ = black_box(header.gid.as_number::<u64>());
        let _ = black_box(header.mtime.as_number::<u64>());
        let _ = black_box(header.typeflag.try_to_type_flag());
    }

    for entry in archive.entries() {
        let _ = black_box(entry.filename().as_str());
        black_box(entry.data());
        let _ = black_box(entry.data_as_str());
        black_box(entry.size());
        black_box(entry.posix_header());
    }
});
