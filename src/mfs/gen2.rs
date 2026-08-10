use core::fmt::{self, Debug, Display};
use core::mem::size_of;

use bitfield_struct::bitfield;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use strum::Display;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

const EXTRACT: bool = true;

const MAGIC: u32 = u32::from_le_bytes(*b"MFS\0");
const PAGE_SIZE: usize = 0x4000;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy)]
#[repr(C)]
pub struct PageFlags(u8);

impl Debug for PageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fl = format!("{:04b}", self.0 & 0xf);
        write!(f, "{fl}")
    }
}

impl Display for PageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fl = self.0 & 0xf;
        // TODO: Those are values seen so far; what do they mean?
        // second bit is always 1 (?)
        // last bit may indicate "dirty"
        let fls = match fl {
            0b0100 => "okay?".to_string(),
            0b0111 => "dirty?".to_string(),
            0b1100 => "live?".to_string(),
            0b1110 => "active?".to_string(),
            _ => format!("{fl:04b}"),
        };
        write!(f, "{fls}")
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct PageHeader {
    pub num: u8,
    pub _1: u8, // 78
    pub flags: PageFlags,
    pub _3: u8,         // ff
    pub all_0: u32,     // not always, can be 01. 2b, 29
    pub magic: [u8; 4], // first page only, ffff otherwise
    // freed_flags: [u8; 0x80],
    // block_itab: [u8; 0x40],
    pub smth: u32, // first page only, ffff otherwise
    pub all_f: u32,
}

impl Display for PageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num = self.num;
        // typically f7, fc, or fe
        let flags = self.flags;
        if num == 0xff && flags.0 == 0xff {
            return write!(f, "page unused");
        }
        write!(f, "page {num:02}, {flags} ({flags:?})")
    }
}

const PAGE_HEADER_SIZE: usize = size_of::<PageHeader>();

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct Page {
    pub header: PageHeader,
    pub indices: Indices,
    pub live_chunks: Vec<Chunk>,
    pub dead_chunks: Vec<Chunk>,
    /// offset in storage
    pub offset: usize,
}

impl Page {
    pub fn is_active(&self) -> bool {
        let n = self.header.num;
        n != 0x00 && n != 0xff
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Display)]
enum ChunkType {
    Rest,
    Data,
    Big,
    BigRest,
    Unknown,
}

impl From<u8> for ChunkType {
    fn from(value: u8) -> Self {
        match value {
            0b1000 => Self::Rest,
            0b1001 => Self::BigRest,
            0b1010 => Self::Data,
            0b1011 => Self::Big,
            _ => Self::Unknown,
        }
    }
}

impl ChunkType {
    // It looks like the first bits are _always_ `10`. Other bits?
    const fn from_bits(val: u8) -> Self {
        match val & 0xf {
            0b1000 => Self::Rest,
            0b1001 => Self::BigRest,
            0b1010 => Self::Data,
            0b1011 => Self::Big,
            _ => Self::Unknown,
        }
    }

    const fn into_bits(self) -> u8 {
        self as u8
    }
}

#[bitfield(u8)]
#[derive(FromBytes, FromZeroes, Serialize, Deserialize)]
pub struct ChunkMeta {
    #[bits(4)]
    file_num: u8,
    #[bits(4)]
    chunk_type: ChunkType,
}

impl ChunkMeta {
    pub fn data_offset(&self) -> usize {
        match self.chunk_type() {
            ChunkType::Data | ChunkType::Big => 5,
            ChunkType::Rest | ChunkType::BigRest => 2,
            _ => 0,
        }
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ChunkHeader {
    pub meta: ChunkMeta,
    pub size: u8,
}

impl Display for ChunkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fnum = self.meta.file_num();
        let sz = self.chunk_size();
        let ct = self.meta.chunk_type();

        write!(f, "{fnum:2}: {ct:4} {sz:5}B")
    }
}

const ALIGNMENT: usize = 16;

impl ChunkHeader {
    pub fn chunk_size(&self) -> usize {
        if self.meta.chunk_type() == ChunkType::Big || self.meta.chunk_type() == ChunkType::BigRest
        {
            self.size as usize * 0x100
        } else {
            self.size as usize
        }
    }

    pub fn data_size(&self) -> usize {
        self.chunk_size() - self.meta.data_offset()
    }

    pub fn aligned(&self) -> usize {
        // chunks are 16-byte aligned, filled with 0xff to the end
        let s = self.chunk_size();
        if s.is_multiple_of(ALIGNMENT) {
            s
        } else {
            s.next_multiple_of(16)
        }
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Chunk {
    pub header: ChunkHeader,
    pub offset: usize,
}

impl Display for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.header;
        let o = self.offset;
        write!(f, "{h} {o:04x}")
    }
}

impl Chunk {
    pub fn is_active(&self) -> bool {
        self.header.meta.file_num() == 0
    }
}

#[derive(
    FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Hash,
)]
pub struct FileId([u8; 3]);

impl Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct FilePath {
    pub page: u8,
    pub offset_key: u8,
    pub file_num: u8,
}

impl Display for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let no = self.file_num;
        let ok = self.offset_key;
        let pg = self.page;

        write!(f, "p{pg:3}/k{ok:3}/n{no:3}")
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct FileEntry {
    pub state: u8,
    pub flags: u8,

    pub id: FileId,

    pub owner: u8, // not sure
    pub size: u16,

    pub path: FilePath,
}

impl Display for FileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.id;
        let sz = self.size;
        let st = self.state;
        let fl = self.flags;
        let ow = self.owner;
        let p = self.path;

        // apparently, some special values occur frequently
        // let m = match st {
        //     0x70fc => "FC",
        //     0x70dc => "DC",
        //     0x70cc => "CC",
        //     0x70c8 => "C8",
        //     _ => "..",
        // };

        // only high 4 bits are set
        let fl = fl >> 4;
        let fli = match fl {
            ..4 => " ",
            _ => "!",
        };

        let stl = st & 0xf;
        let sth = st >> 4;
        let tt = format!("{st:02x} ({sth:04b} {stl:04b})");

        write!(f, "{id} {sz:5} {ow:02x}  {p}  {tt}, {fl:04b}{fli}")
    }
}

const INDICES_SIZE: usize = 0x40;

#[derive(FromBytes, FromZeroes, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct Indices(#[serde(with = "serde_bytes")] [u8; INDICES_SIZE]);

const SMTH_SIZE: usize = size_of::<FileEntry>();

// TODO: evaluate header length, separate from page 0
const PAGE_HEADER_LENGTH: usize = 0x90;
const CHUNK_OFFSET: usize = PAGE_HEADER_LENGTH + INDICES_SIZE;

const BLOCK_SIZE: usize = 0x100;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Display)]
pub enum DataReadError {
    NotInPage,
    UnexpectedChunkSize,
    UnexpectedChunkOffset,
    UnknownChunk,
    ChunkParseError,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Display)]
pub enum DataReadResult {
    Done,
    Need(FilePath),
}

pub fn read_data(
    data: &[u8],
    page: &Page,
    file_path: &FilePath,
    file_size: usize,
    res: &mut Vec<u8>,
) -> Result<DataReadResult, DataReadError> {
    let n = page.header.num;
    let po = page.offset;
    // file offset key -> index translation
    let k = file_path.offset_key as usize;
    let i = page.indices.0[k];
    // base offset
    let bo = i as usize * BLOCK_SIZE;
    // chunk offset
    let mut co = if bo == 0 { CHUNK_OFFSET } else { bo };

    println!("Read data for path {file_path}, start seeking");
    println!("  page {n} @{po:08x}; {k} -> {i} / {bo:04x}|{co:04x}");

    if co >= PAGE_SIZE {
        return Err(DataReadError::UnexpectedChunkOffset);
    }
    let flen = file_size;
    let Some(mut h) = ChunkHeader::read_from_prefix(&data[co..]) else {
        return Err(DataReadError::ChunkParseError);
    };

    let mut remaining = flen - res.len();
    let mut seek = true;

    println!("seek, remaining: {remaining}");
    loop {
        // seek to first chunk belonging to file
        while seek && h.meta.file_num() != file_path.file_num {
            println!("Skipping             {h} @ {:08x}", po + co);
            // next offset
            co += h.aligned();
            if co > PAGE_SIZE - ALIGNMENT {
                return Err(DataReadError::NotInPage);
            }
            if h.meta.chunk_type() == ChunkType::Unknown {
                return Err(DataReadError::UnknownChunk);
            }
            h = ChunkHeader::read_from_prefix(&data[co..]).unwrap();
        }
        seek = false;

        // A chunk must not cross the page boundary.
        if co + h.chunk_size() > PAGE_SIZE {
            return Err(DataReadError::UnexpectedChunkSize);
        }

        let read_size = h.data_size().min(remaining);
        println!("Reading {read_size:4} bytes / {h} @ {:08x}", po + co);
        let cdo = h.meta.data_offset();
        let o = co + cdo;
        res.extend_from_slice(&data[o..o + read_size]);
        remaining = flen - res.len();

        // TODO: handle the Rust way
        if cdo == 5 {
            let p = FilePath::read_from_prefix(&data[co + 2..]).unwrap();
            // continue to read from respective page
            return Ok(DataReadResult::Need(p));
        }

        // We are done if we reached the desired length of the file.
        if remaining == 0 {
            return Ok(DataReadResult::Done);
        }

        // Look at the next offset / chunk.
        co += h.aligned();
        if co > PAGE_SIZE - ALIGNMENT {
            return Err(DataReadError::UnexpectedChunkSize);
        }
        if h.meta.chunk_type() == ChunkType::Unknown {
            return Err(DataReadError::UnknownChunk);
        }
        h = ChunkHeader::read_from_prefix(&data[co..]).unwrap();
    }
}

fn process_file(i: usize, file: &FileEntry, pages: &[Page], data: &[u8]) {
    let id = file.id;
    let sz = file.size;
    let mut file_path = file.path;

    let mut d = vec![];

    let ono = file_path.file_num;
    loop {
        let no = file_path.file_num;
        // TODO: handle error
        let p = pages
            .iter()
            .find(|p| p.header.num == file_path.page)
            .unwrap();
        let po = p.offset;

        let page_data = &data[po..po + PAGE_SIZE];
        match read_data(page_data, p, &file_path, file.size as usize, &mut d) {
            Ok(DataReadResult::Done) => {
                let all_read = sz as usize == d.len();
                let a = if all_read { "OK" } else { "NO" };
                println!("File #{i:3} / {id}_{no}: read {}/{sz} {a}", d.len());

                if EXTRACT {
                    use std::fs::File;
                    use std::io::Write;

                    let mut f = File::create(format!("xdump/{id}_{ono}.bin")).unwrap();
                    f.write_all(&d).unwrap();
                }

                break;
            }
            Ok(DataReadResult::Need(p)) => {
                println!("File #{i:3} / {id}_{no}: read {}/{sz}, need more", d.len());
                file_path = p;
            }
            Err(e) => {
                println!("File #{i:3} / {id}_{no}: read {}/{sz}, error {e}", d.len());
                return;
            }
        }
    }
}

pub fn parse(data: &[u8], verbose: bool) -> Result<bool, String> {
    let size = data.len();
    println!("Trying to parse MFS for Gen 2, size: {size:08x}");

    if !size.is_multiple_of(PAGE_SIZE) {
        return Err(format!("Size is not a multiple of page size ({PAGE_SIZE})"));
    }

    let mut pages = Vec::<Page>::new();
    let mut log = Vec::<FileEntry>::new();

    // TODO: separate first page already
    for offset in (0..size).step_by(PAGE_SIZE) {
        let slice = &data[offset..offset + PAGE_SIZE];
        let Some(header) = PageHeader::read_from_prefix(slice) else {
            return Err(format!("Could not read header of page @ {offset:08x}"));
        };

        let mut live_chunks = Vec::<Chunk>::new();
        let mut dead_chunks = Vec::<Chunk>::new();

        let mut pos = CHUNK_OFFSET;

        let n = header.num;
        if n > 0 && n != 0xff {
            if verbose {
                println!("page {n}: read chunks...");
            }
            let mut dead = false;
            loop {
                if pos >= PAGE_SIZE {
                    if verbose {
                        println!("  read all chunks, reached {pos:04x}");
                    }
                    break;
                }
                let o = offset + pos;
                let ch = ChunkHeader::read_from_prefix(&data[o..]).unwrap();
                let m: u8 = ch.meta.into();
                if m == 0xff || ch.size == 0 {
                    if verbose {
                        println!("  no chunk @ {pos:04x}; size {:04}, meta {m:02x?}", ch.size,);
                    }
                    // break;
                    // NOTE: those may be "dead" chunks
                    pos += 16;
                    dead = true;
                    continue;
                }
                let co = pos - CHUNK_OFFSET;
                let c = Chunk {
                    header: ch,
                    offset: co,
                };
                if verbose {
                    println!("  chunk @ {pos:04x}: {c}");
                }
                if dead {
                    dead_chunks.push(c);
                } else {
                    live_chunks.push(c);
                }
                if verbose && ch.meta.chunk_type() == ChunkType::Big {
                    let x8 = &data[o + 2..o + 10];
                    // NOTE: 3rd byte is always 0x00
                    // Examples:
                    // b0: [0b, 05, 00, 04, 00, 00, 00, 00]
                    // b0: [0b, 12, 00, 00, 00, 00, 00, 00]
                    // b0: [0c, 00, 00, e0, 7a, 33, 95, 52]
                    // b0: [0d, 00, 00, 87, 54, 7d, d8, ec]
                    // b0: [14, 05, 00, 00, ff, ff, ff, ff]
                    // b0: [14, 10, 00, 00, 0c, 00, 00, 04]
                    // b0: [14, 1d, 00, 00, e7, 03, 00, 00]
                    println!("  b0: {x8:02x?}");
                }
                pos += ch.aligned();
            }
        } else if verbose {
            println!("  no chunks to read");
        }
        let indices = Indices::read_from_prefix(&slice[PAGE_HEADER_LENGTH..]).unwrap();

        let p = Page {
            header,
            live_chunks,
            dead_chunks,
            indices,
            offset,
        };

        pages.push(p);
    }

    pages.sort_by_key(|p| p.header.num);

    if false {
        use std::io::Write;
        let mut file = std::fs::File::create("sorted.bin").unwrap();
        for p in &pages {
            let o = p.offset;
            let p = &data[o..o + PAGE_SIZE];
            file.write_all(p).unwrap();
        }
    }

    // first page has MFS magic and some sort of metadata
    let mut i = 0;
    if let Some(p0) = pages.first() {
        let m = u32::from_le_bytes(p0.header.magic);
        if m != MAGIC {
            return Err("Gen2 MFS: page 0 does not have expected magic".to_string());
        } else {
            loop {
                let pos = p0.offset + PAGE_HEADER_SIZE + i * SMTH_SIZE;
                let smth = FileEntry::read_from_prefix(&data[pos..]).unwrap();
                if smth.flags == 0xff && smth.state == 0xff {
                    // no idea yet how to get the length here
                    break;
                }
                log.push(smth);
                i += 1;
            }
        }
    }

    println!();
    println!("== List of files (page 0)");
    /*
    log.sort_by(|a, b| {
        let na = a._0;
        let nb = b._0;
        na.cmp(&nb)
    });
    log.sort_by(|a, b| {
        let na = a.id;
        let nb = b.id;
        na.cmp(&nb)
    });
    log.sort_by(|a, b| {
        let na = a._9;
        let nb = b._9;
        na.cmp(&nb)
    });
    */

    for (i, s) in log.iter().enumerate() {
        println!("{i:04}: {s}");
    }
    println!();

    let unique = log.iter().map(|i| i.id).collect::<HashSet<_>>();

    println!("{} entries, {} unique", log.len(), unique.len());
    println!();

    let mut total_live_chunks = 0;
    let mut total_dead_chunks = 0;
    let mut total_active_chunks = 0;
    for p in &pages {
        let h = p.header;
        let lcs = p.live_chunks.len();
        let dcs = p.dead_chunks.len();
        let po = p.offset;
        println!("{h} @ {po:08x}");
        total_live_chunks += lcs;
        total_dead_chunks += dcs;

        if p.is_active() {
            for b in (0..0x40).step_by(0x10) {
                println!("    {:02x?}", &p.indices.0[b..b + 0x10]);
            }
            let fc: Vec<Chunk> = p
                .live_chunks
                .clone()
                .into_iter()
                .filter(|c| c.is_active())
                .collect();
            let acs = fc.len();
            total_active_chunks += acs;

            println!("{lcs} live chunks, {acs} active");
            if lcs > 0 {
                for (i, c) in p.live_chunks.iter().enumerate() {
                    if i > 0 && i % 4 == 0 {
                        println!(" |");
                    }
                    let b = if c.is_active() {
                        // first actual data byte
                        let b = data[po + CHUNK_OFFSET + c.offset + 2];
                        format!("{b:02x}")
                    } else {
                        "  ".to_string()
                    };
                    print!(" | {c} {b}");
                }
                println!(" |");
            }
            println!("{dcs} dead chunks");
            if dcs > 0 {
                for (i, c) in p.dead_chunks.iter().enumerate() {
                    if i > 0 && i % 4 == 0 {
                        println!(" |");
                    }
                    print!(" | {c}");
                }
                println!(" |");
            }
        }
        println!();
    }
    let ps = pages.len();
    println!("{ps} pages");
    println!("{total_live_chunks} live chunks total, {total_active_chunks} active");
    println!("{total_dead_chunks} dead chunks total");

    if true {
        for i in 0..140 {
            let file = log.get(i).unwrap();
            process_file(i, file, &pages, data);
            println!();
        }
    }

    // let i = 92;
    // let file = log.get(i).unwrap();
    // process_file(i, file, &pages, data);

    Ok(true)
}
