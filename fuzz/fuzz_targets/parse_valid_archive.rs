#![no_main]

use core::ops::Range;

use libfuzzer_sys::fuzz_target;
use tar_no_std::TarArchiveRef;

mod exercise;

const BLOCK_SIZE: usize = 512;
const CHECKSUM: Range<usize> = 148..156;
const TYPE_FLAG: usize = 156;
const MAX_ENTRIES: usize = 4;

struct Entry<'a> {
    metadata: &'a [u8],
    payload: &'a [u8],
    kind: EntryKind,
    size_encoding: OctalEncoding,
    checksum_encoding: OctalEncoding,
}

#[derive(Copy, Clone, Debug)]
enum EntryKind {
    Regular,
    LegacyRegular,
    Link,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Directory,
    Fifo,
    Contiguous,
    PaxExtended,
    PaxGlobal,
}

impl EntryKind {
    const fn from_byte(byte: u8) -> Self {
        match byte % 11 {
            0 => Self::Regular,
            1 => Self::LegacyRegular,
            2 => Self::Link,
            3 => Self::SymbolicLink,
            4 => Self::CharacterDevice,
            5 => Self::BlockDevice,
            6 => Self::Directory,
            7 => Self::Fifo,
            8 => Self::Contiguous,
            9 => Self::PaxExtended,
            _ => Self::PaxGlobal,
        }
    }

    const fn type_flag(self) -> u8 {
        match self {
            Self::Regular => b'0',
            Self::LegacyRegular => b'\0',
            Self::Link => b'1',
            Self::SymbolicLink => b'2',
            Self::CharacterDevice => b'3',
            Self::BlockDevice => b'4',
            Self::Directory => b'5',
            Self::Fifo => b'6',
            Self::Contiguous => b'7',
            Self::PaxExtended => b'x',
            Self::PaxGlobal => b'g',
        }
    }

    const fn has_payload(self) -> bool {
        matches!(
            self,
            Self::Regular
                | Self::LegacyRegular
                | Self::Contiguous
                | Self::PaxExtended
                | Self::PaxGlobal
        )
    }
}

#[derive(Copy, Clone, Debug)]
enum OctalEncoding {
    NullTerminated,
    SpaceTerminated,
    NullSpaceTerminated,
}

impl OctalEncoding {
    const fn from_byte(byte: u8) -> Self {
        match byte % 3 {
            0 => Self::NullTerminated,
            1 => Self::SpaceTerminated,
            _ => Self::NullSpaceTerminated,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let bytes = build_archive(data);
    let archive = TarArchiveRef::new(&bytes)
        .expect("the structure-aware generator must produce a valid archive");
    exercise::archive(&archive);
});

fn build_archive(data: &[u8]) -> Vec<u8> {
    let entry_count = usize::from(data.first().copied().unwrap_or(0)) % MAX_ENTRIES + 1;
    let material = data.get(1..).unwrap_or_default();
    let mut archive = Vec::new();

    for index in 0..entry_count {
        let start = material.len() * index / entry_count;
        let end = material.len() * (index + 1) / entry_count;
        let entry_material = &material[start..end];
        let split = entry_material.len() / 2;
        let control = |offset| data.get(1 + index * 3 + offset).copied().unwrap_or(0);
        let entry = Entry {
            metadata: &entry_material[..split],
            payload: &entry_material[split..],
            kind: EntryKind::from_byte(control(0)),
            size_encoding: OctalEncoding::from_byte(control(1)),
            checksum_encoding: OctalEncoding::from_byte(control(2)),
        };
        append_entry(&mut archive, &entry);
    }

    archive.resize(archive.len() + 2 * BLOCK_SIZE, 0);
    archive
}

fn append_entry(archive: &mut Vec<u8>, entry: &Entry<'_>) {
    let mut header = [0; BLOCK_SIZE];
    if !entry.metadata.is_empty() {
        for (byte, value) in header.iter_mut().zip(entry.metadata.iter().cycle()) {
            *byte = *value;
        }
    }

    header[TYPE_FLAG] = entry.kind.type_flag();
    if entry.kind.has_payload() {
        write_octal(
            &mut header[124..136],
            entry.payload.len() as u64,
            entry.size_encoding,
        );
    }

    header[CHECKSUM.clone()].fill(b' ');
    let checksum = header.iter().copied().map(u64::from).sum();
    write_octal(
        &mut header[CHECKSUM.clone()],
        checksum,
        entry.checksum_encoding,
    );

    archive.extend_from_slice(&header);
    if entry.kind.has_payload() {
        archive.extend_from_slice(entry.payload);
        let padding = archive.len().next_multiple_of(BLOCK_SIZE) - archive.len();
        archive.resize(archive.len() + padding, 0);
    }
}

fn write_octal(field: &mut [u8], value: u64, encoding: OctalEncoding) {
    let value = format!("{value:o}");
    let suffix = match encoding {
        OctalEncoding::NullTerminated | OctalEncoding::SpaceTerminated => 1,
        OctalEncoding::NullSpaceTerminated => 2,
    };
    let digits = field.len() - suffix;

    // Checksum is a sum of 512 bytes each 0..=255, so max value is
    // 512*255 = 130_560 = 0o377_000 (6 octal digits) - fits in the checksum
    // field's tightest encoding (6 digits + 2-byte suffix). Re-derive this
    // if the checksum formula changes.
    assert!(value.len() <= digits);

    field[..digits].fill(b'0');
    field[digits - value.len()..digits].copy_from_slice(value.as_bytes());
    match encoding {
        OctalEncoding::NullTerminated => field[digits] = b'\0',
        OctalEncoding::SpaceTerminated => field[digits] = b' ',
        OctalEncoding::NullSpaceTerminated => {
            field[digits] = b'\0';
            field[digits + 1] = b' ';
        }
    }
}
