use core::fmt::{self, Debug, Display};
use core::mem::size_of;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

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
    pub smth: u32,      // first page only, ffff otherwise
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
    // #[serde(with = "serde_bytes")]
    // pub indices: [u8; 0x40],
    pub live_chunks: Vec<Chunk>,
    pub dead_chunks: Vec<Chunk>,
    pub offset: usize,
}

impl Page {
    pub fn is_active(&self) -> bool {
        let n = self.header.num;
        n != 0x00 && n != 0xff
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ChunkHeader {
    pub flags: u8,
    pub size: u8,
}

impl Display for ChunkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fl = self.flags;
        // It looks like the first bits are _always_ `10`.
        let f0 = (fl >> 4) & 0b11;
        // Does f1 == 0 mean "active"? The number of such matches with the
        // number of non-ff indices that appear from the beginning (non-dirty?),
        // at least in the samples seen so far.
        let f1 = fl & 0b1111;
        let sz = self.size();
        // It looks like whenever f1 == 0, then f0 is either 0, 2 or 3, never 1.
        // 0 occurs most frequently in the samples so far. 3 means a big chunk.
        let tt = match (f0, f1) {
            (0, 0) => "F", // most frequent
            (2, 0) => "X",
            (3, 0) => "B", // big chunk
            _ => " ",
        };

        write!(f, "{fl:02x} {tt} {sz:5} ({sz:04x})")
    }
}

impl ChunkHeader {
    pub fn size(&self) -> usize {
        // NOTE: This works _so far_.
        if self.size > 2 && self.flags != 0xb0 {
            let s = self.size as usize;
            // selfunks are 16-byte aligned, filled with 0xff to the end
            let sm = s % 16;
            if sm == 0 {
                s
            } else {
                s + 16 - sm
            }
        } else {
            self.size as usize * 0x100
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
        self.header.flags & 0b1111 == 0
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct LogEntry {
    pub _0: u16,
    pub id: u8,
    pub _3: u16,
    pub _5: u16,
    pub _7: u16,
    pub _9: u16,
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // apparently, some special values occur frequently
        let t = self._0;
        let id = self.id;
        let d = self._3;
        let v = self._5;
        let c = self._7;
        let x = self._9;

        let m = match t {
            0x70fc => "FC",
            0x70dc => "DC",
            0x70cc => "CC",
            0x70c8 => "C8",
            _ => "..",
        };

        let ii = match id {
            ..0x40 => " ",
            _ => "!",
        };

        let ff = 0xffff;
        let xor = format!(
            "{:04x} {:02x} {:04x} {:04x} {:04x} {:04x}",
            t ^ ff,
            id ^ 0xff,
            d ^ ff,
            v ^ ff,
            c ^ ff,
            x ^ ff
        );

        let t0 = t >> 8;
        let t1 = t & 0xff;
        let t0a = t0 & 0xf;
        let t0b = t0 >> 4;
        let t1a = t1 & 0xf;
        let t1b = t1 >> 4;

        let tt = format!("{t0a:04b} {t0b:04b} {t1a:04b} {t1b:04b}");

        write!(
            f,
            "{t:04x} ({tt}) {id:02x}  {d:04x} {v:04x} {c:04x} {x:04x}  {m} {ii}  {xor}"
        )
    }
}

const INDICES_SIZE: usize = 0x40;

#[derive(FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Indices([u8; INDICES_SIZE]);

const SMTH_SIZE: usize = size_of::<LogEntry>();

// TODO: evaluate header length, separate from page 0
const PAGE_HEADER_LENGTH: usize = 0x90;
const CHUNK_OFFSET: usize = PAGE_HEADER_LENGTH + INDICES_SIZE;

pub fn parse(data: &[u8], verbose: bool) -> Result<bool, String> {
    let size = data.len();
    println!("Trying to parse MFS for Gen 2, size: {size:08x}");

    if size % PAGE_SIZE != 0 {
        return Err(format!("Size is not a multiple of page size ({PAGE_SIZE})"));
    }

    let mut pages = Vec::<Page>::new();
    let mut log = Vec::<LogEntry>::new();

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
                if ch.flags == 0xff || ch.size == 0 {
                    if verbose {
                        println!("  no chunk @ {pos:04x}");
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
                if verbose && ch.flags == 0xb0 {
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
                pos += ch.size();
            }
        } else if verbose {
            println!("  no chunks to read");
        }

        let p = Page {
            header,
            live_chunks,
            dead_chunks,
            offset,
        };

        pages.push(p);
    }

    pages.sort_by(|a, b| {
        let na = a.header.num;
        let nb = b.header.num;
        na.cmp(&nb)
    });

    // first page has MFS magic and some sort of metadata
    let mut i = 0;
    if let Some(p0) = pages.first() {
        let m = u32::from_le_bytes(p0.header.magic);
        if m != MAGIC {
            return Err("Gen2 MFS: page 0 does not have expected magic".to_string());
        } else {
            loop {
                let pos = p0.offset + PAGE_HEADER_SIZE + i * SMTH_SIZE;
                let smth = LogEntry::read_from_prefix(&data[pos..]).unwrap();
                if smth._0 == 0xffff {
                    // no idea yet how to get the length here
                    break;
                }
                log.push(smth);
                i += 1;
            }
        }
    }

    println!();
    println!("== Log or smth (page 0)");
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
            let d = Indices::read_from_prefix(&data[po + PAGE_HEADER_LENGTH..]).unwrap();
            for b in (0..0x40).step_by(0x10) {
                println!("    {:02x?}", &d.0[b..b + 0x10]);
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

    Ok(true)
}
