// SPDX-License-Identifier: MIT

use core::hint::black_box;

use tar_no_std::{MIN_BLOCK_COUNT, StreamEvent, TarArchiveRef, TarStreamParser};

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

pub fn stream(data: &[u8]) {
    if data.len() % 512 != 0 || data.len() / 512 < MIN_BLOCK_COUNT {
        return;
    }

    let mut parser = TarStreamParser::new();
    let mut header_blocks = Vec::new();
    let mut files = Vec::new();
    let mut result = Ok(());
    for block in data.chunks_exact(512) {
        match parser.parse_block(block.try_into().unwrap()) {
            Ok(Some(StreamEvent::Entry(entry))) => {
                assert!(entry.type_flag().is_regular_file());
                header_blocks.push(entry.block_index());
                files.push((entry.filename(), Vec::new()));
            }
            Ok(Some(StreamEvent::Data { bytes, .. })) => {
                files.last_mut().unwrap().1.extend_from_slice(bytes);
            }
            Ok(Some(StreamEvent::End)) => break,
            Ok(None) => {}
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    let result = result.and(parser.finish());

    match TarArchiveRef::new(data) {
        Ok(archive) => {
            assert_eq!(result, Ok(()));
            let expected_header_blocks = archive
                .headers()
                .filter(|(_, header)| {
                    header
                        .typeflag
                        .try_to_type_flag()
                        .is_ok_and(|type_flag| type_flag.is_regular_file())
                })
                .map(|(block_index, _)| block_index)
                .collect::<Vec<_>>();
            assert_eq!(header_blocks, expected_header_blocks);
            let expected_files = archive
                .entries()
                .map(|entry| (entry.filename(), entry.data().to_vec()))
                .collect::<Vec<_>>();
            assert_eq!(files, expected_files);
        }
        Err(error) => assert_eq!(result, Err(error)),
    }
}
