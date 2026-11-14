// SPDX-License-Identifier: MIT

use core::convert::Infallible;
use core::hint::black_box;

use tar_no_std::{BLOCKSIZE, StreamError, TarArchiveRef, TarFormatString, TarStreamReader};

const FILENAME_LEN: usize = 256;

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
    // Vary the buffer size to exercise partial payload reads.
    let chunk_size = data.len() % 97 + 1;
    let result = read_with_reader(data, chunk_size);

    // Unlike the reader, TarArchiveRef also rejects inputs that are not made
    // of whole blocks.
    if data.len() % BLOCKSIZE != 0 {
        return;
    }
    let expected = TarArchiveRef::new(data)
        .map(|archive| {
            archive
                .entries()
                .map(|entry| (entry.filename(), entry.data().to_vec()))
                .collect::<Vec<_>>()
        })
        .map_err(StreamError::Corrupt);
    assert_eq!(result, expected);
}

type Files = Vec<(TarFormatString<FILENAME_LEN>, Vec<u8>)>;

fn read_with_reader(data: &[u8], chunk_size: usize) -> Result<Files, StreamError<Infallible>> {
    let mut blocks = data.chunks_exact(BLOCKSIZE);
    let mut reader = TarStreamReader::new(|buf: &mut [u8; BLOCKSIZE]| {
        let Some(block) = blocks.next() else {
            return Ok(false);
        };
        buf.copy_from_slice(block);
        Ok(true)
    });
    let mut files = Vec::new();
    let mut buf = vec![0; chunk_size];
    while let Some(mut entry) = reader.next_entry()? {
        let mut data = Vec::new();
        loop {
            let n = entry.read_payload(&mut buf)?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        assert_eq!(data.len(), entry.size());
        files.push((entry.filename(), data));
    }
    Ok(files)
}
