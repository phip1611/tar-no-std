use core::hint::black_box;

use tar_no_std::TarArchiveRef;

pub fn archive(archive: &TarArchiveRef<'_>) {
    for (_, header) in archive.headers() {
        let _ = black_box(header.name.as_str());
        let _ = black_box(header.mode.to_flags());
        let _ = black_box(header.uid.as_number::<u64>());
        let _ = black_box(header.gid.as_number::<u64>());
        let _ = black_box(header.size.as_number::<u64>());
        let _ = black_box(header.mtime.as_number::<u64>());
        let _ = black_box(header.cksum.as_number::<u64>());

        let type_flag = header.typeflag.try_to_type_flag();
        if let Ok(type_flag) = type_flag {
            black_box(type_flag.is_regular_file());
        }
        let _ = black_box(type_flag);

        let _ = black_box(header.linkname.as_str());
        let _ = black_box(header.magic.as_str());
        let _ = black_box(header.version.as_str());
        let _ = black_box(header.uname.as_str());
        let _ = black_box(header.gname.as_str());
        let _ = black_box(header.dev_major.as_number::<u64>());
        let _ = black_box(header.dev_minor.as_number::<u64>());
        let _ = black_box(header.prefix.as_str());
        black_box(header._pad);
        let _ = black_box(header.payload_block_count());
        black_box(header.is_zero_block());
    }

    for entry in archive.entries() {
        let _ = black_box(entry.filename().as_str());
        black_box(entry.data());
        let _ = black_box(entry.data_as_str());
        black_box(entry.size());
        black_box(entry.posix_header());
    }
}
