use core::fmt::{self, Display};
use core::mem::size_of;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

const MAGIC: u32 = u32::from_le_bytes(*b"MFS\0");
const PAGE_SIZE: usize = 0x4000;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct PageFlags(u8);

impl Display for PageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fl = self.0 & 0xf;
        // TODO: Those are values seen so far; what do they mean?
        let fls = match fl {
            0x7 => "xxx7".to_string(),
            0xc => "xxxC".to_string(),
            0xe => "xxxE".to_string(),
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
        write!(f, "page {num:02}, flag {flags}")
    }
}

const PAGE_HEADER_SIZE: usize = size_of::<PageHeader>();

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct Page {
    pub header: PageHeader,
    // pub indices: Indices,
    pub chunks: Vec<Chunk>,
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
        // looks like the first bits are _always_ `10`.
        let f0 = (fl >> 4) & 0b11;
        let f1 = fl & 0b1111;
        let sz = self.size();
        // does this mean "active"?
        let fb = match f1 {
            0b0000 => "  A ".to_string(),
            _ => format!("{f1:04b}"),
        };
        let id = fl & 0b111111;
        write!(f, "{id:02x} {f0:02b} {fb} {sz:4}")
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
#[repr(C, packed)]
pub struct Chunk {
    pub header: ChunkHeader,
    pub offset: usize,
}

impl Display for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.header;
        let o = self.offset;
        // TODO: offset
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

        write!(
            f,
            "{t:04x}  {id:02x}  {d:04x} {v:04x} {c:04x} {x:04x}  {m}  {xor}"
        )
    }
}

#[derive(FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Indices([u8; 0x40]);

const SMTH_SIZE: usize = size_of::<LogEntry>();

pub fn parse(data: &[u8], verbose: bool) -> Result<bool, String> {
    let size = data.len();
    println!("Trying to parse MFS for Gen 2, size: {size:08x}");

    let mut pages = Vec::<Page>::new();
    let mut log = Vec::<LogEntry>::new();

    for offset in (0..size).step_by(PAGE_SIZE) {
        let slice = &data[offset..offset + PAGE_SIZE];
        let Some(header) = PageHeader::read_from_prefix(slice) else {
            return Err(format!("could not read header of page @ {offset:08x}"));
        };

        let mut chunks = Vec::<Chunk>::new();

        let mut pos = 0xd0;

        let n = header.num;
        if n > 0 && n != 0xff {
            println!("page {n:03}: read chunks...");
            loop {
                if pos >= PAGE_SIZE {
                    println!("page {n:03}: read all chunks, reached {pos:08x}");
                    break;
                }
                let o = offset + pos;
                let ch = ChunkHeader::read_from_prefix(&data[o..]).unwrap();
                if ch.flags == 0xff || ch.size == 0 {
                    if verbose {
                        println!("page {n:03}: no chunk @ {pos:08x}, {ch}");
                    }
                    // break;
                    // NOTE: those may be "dead" chunks
                    pos += 16;
                    continue;
                }
                let size = ch.size();
                let c = Chunk {
                    header: ch,
                    offset: pos,
                };
                chunks.push(c);

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
                    println!("b0: {x8:02x?}");
                }
                pos += size;
            }
        } else {
            println!("page {n:03}: no chunks to read");
        }

        let p = Page {
            header,
            chunks,
            offset,
        };

        pages.push(p);
    }

    pages.sort_by(|a, b| {
        let na = a.header.num;
        let nb = b.header.num;
        na.cmp(&nb)
    });

    let mut total_chunks = 0;
    let mut active_chunks = 0;
    for p in &pages {
        let h = p.header;
        let cs = p.chunks.len();
        let po = p.offset;
        println!("{h} @ {po:08x}, {cs} chunks");
        total_chunks += cs;

        if p.is_active() {
            // TODO: evaluate header length, separate from page 0
            const PAGE_HEADER_LENGTH: usize = 0x90;
            let d = Indices::read_from_prefix(&data[po + PAGE_HEADER_LENGTH..]).unwrap();
            for b in (0..0x40).step_by(0x10) {
                println!("    {:02x?}", &d.0[b..b + 0x10]);
            }
            let fc: Vec<Chunk> = p
                .chunks
                .clone()
                .into_iter()
                .filter(|c| c.is_active())
                .collect();
            let acs = fc.len();
            println!("{acs} active chunks");
            active_chunks += acs;

            for (i, c) in p.chunks.iter().enumerate() {
                if i > 0 && i % 8 == 0 {
                    println!(" |");
                }
                print!(" | {c}");
            }
            println!(" |");
        }
        println!();
    }
    let ps = pages.len();
    println!("{ps} pages, {total_chunks} chunks total, {active_chunks} active");
    println!();

    // first page has MFS magic and some sort of metadata
    let mut i = 0;
    if let Some(p0) = pages.first() {
        let m = u32::from_le_bytes(p0.header.magic);
        if m != MAGIC {
            println!("Gen2 MFS: page 0 does not have expected magic");
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

    /*
    log.sort_by(|a, b| {
        let na = a._0;
        let nb = b._0;
        na.cmp(&nb)
    });
    log.sort_by(|a, b| {
        let na = a._9;
        let nb = b._9;
        na.cmp(&nb)
    });
    log.sort_by(|a, b| {
        let na = a.id;
        let nb = b.id;
        na.cmp(&nb)
    });
    */

    for (i, s) in log.iter().enumerate() {
        println!("{i:04}: {s}");
    }

    let unique = log.iter().map(|i| i.id).collect::<HashSet<_>>();

    println!("{} entries, {} unique", log.len(), unique.len());
    println!();

    Ok(true)
}
