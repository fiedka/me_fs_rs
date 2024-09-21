use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

// see https://live.ructf.org/intel_me.pdf slide 35
const PAGE_MAGIC: u32 = 0xaa55_7887;

pub const PAGE_SIZE: usize = 0x2000;
// XXX: this yields 20... why?
pub const PAGE_HEADER_SIZE: usize = std::mem::size_of::<PageHeader>();

// NOTE: We cannot use PAGE_HEADER_SIZE here because it is larger than the
// underlying data.
const SLOTS_OFFSET: usize = 18;
// NOTE: System and data pages have different chunk counts and different slot sizes!
const SYS_CHUNKS_OFFSET: usize = SLOTS_OFFSET + 2 * SYS_PAGE_SLOTS;
const DATA_CHUNKS_OFFSET: usize = SLOTS_OFFSET + DATA_PAGE_SLOTS;

pub const CHUNK_DATA_SIZE: usize = 0x40;
// + 2 bytes checksum
pub const CHUNK_SIZE: usize = CHUNK_DATA_SIZE + 2;

pub const SYS_PAGE_CHUNKS: usize = 120;
pub const SYS_PAGE_SLOTS: usize = SYS_PAGE_CHUNKS + 1;

pub const DATA_PAGE_CHUNKS: usize = 122;
pub const DATA_PAGE_SLOTS: usize = DATA_PAGE_CHUNKS;

pub const SLOT_UNUSED: u16 = 0xffff;
pub const SLOT_LAST: u16 = 0x7fff;

pub const VOL_MAGIC: u32 = 0x724F_6201;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct PageHeader {
    pub magic: [u8; 4],
    // update sequence number
    pub usn: u32,
    pub n_erase: u32,
    pub i_next_erase: u16,
    pub first_chunk: u16, // first chunk index, for data
    pub checksum: u8,
    pub b0: u8, // always 0
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Chunk {
    #[serde(with = "BigArray")]
    pub data: [u8; CHUNK_DATA_SIZE],
    pub crc16: u16,
}

pub type Chunks = BTreeMap<u16, Chunk>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct SysPage {
    pub offset: usize,
    pub header: PageHeader,
    pub chunks: Chunks,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct DataPage {
    pub offset: usize,
    pub header: PageHeader,
    pub chunks: Chunks,
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct VolHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub chunk_bytes_total: u32,
    pub files: u16,
}

/*
data areas

Iterate over all data pages
  nSysChunks = min(nSysPages, pg.hdr.firstChunk)
    Iterate over all used chunks on the current page
      dataChunks[pg.hdr.firstChunk + i] = pg.chunks[i].data

system area

Iterate over system pages in ascending USN order
  Iterate over all used chunks on the current page
    Calculate chunk size (iChunk) based on pg.axIdx[i]
    sysArea[iChunk*64 : (iChunk+1)*64] = pg.chunks[i].data
*/

// *CCITT CRC-16 is calculated from the chunk data and the 16-bit (2-byte) chunk index
// https://srecord.sourceforge.net/crc16-ccitt.html
const CCITT: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut r = i << 8;
        for _ in 0..8 {
            let poly = if r & 0x8000 != 0 { 0x1021 } else { 0 };
            r = (r << 1) ^ poly;
        }
        *e = r as u16;
    }
    table
}

fn crc_idx(v: u16) -> u16 {
    let tab = crc_table();

    let v = [v as u8, (v >> 8) as u8];

    let mut crc: u16 = 0x3fff;
    for b in v {
        let i = (b as u16 ^ (crc >> 8)) as u8 as usize;
        crc = (tab[i] ^ (crc << 8)) & 0x3fff;
    }
    crc
}

fn parse_data_chunks(data: &[u8], first_chunk: u16) -> (Chunks, usize) {
    let mut free_chunks = 0;
    let mut chunks = Chunks::new();

    for chunk_pos in 0..DATA_PAGE_SLOTS {
        let o = SLOTS_OFFSET + chunk_pos;
        let s = u8::read_from_prefix(&data[o..]).unwrap();

        // free chunk
        if s == 0xff {
            free_chunks += 1;
            continue;
        }

        let chunk_index = first_chunk + chunk_pos as u16;

        // Parse the chunk
        let coff = DATA_CHUNKS_OFFSET + chunk_pos * CHUNK_SIZE;
        let cbuf = &data[coff..coff + CHUNK_SIZE];
        let c = Chunk::read_from_prefix(cbuf).unwrap();

        chunks.insert(chunk_index, c);
    }
    (chunks, free_chunks)
}

fn parse_sys_chunks(data: &[u8]) -> (Chunks, usize) {
    let mut free_chunks = 0;
    let mut chunks = Chunks::new();
    let mut chunk_index = 0;

    for chunk_pos in 0..SYS_PAGE_SLOTS {
        let o = SLOTS_OFFSET + 2 * chunk_pos;
        let slot = u16::read_from_prefix(&data[o..]).unwrap();

        if slot == SLOT_UNUSED {
            free_chunks += 1;
            continue;
        }
        // Last chunk is marked
        if slot == SLOT_LAST {
            let remaining = SYS_PAGE_CHUNKS - chunk_pos;
            free_chunks += remaining;
            break;
        }

        // Parse the chunk
        let coff = SYS_CHUNKS_OFFSET + chunk_pos * CHUNK_SIZE;
        let cbuf = &data[coff..coff + CHUNK_SIZE];
        let c = Chunk::read_from_prefix(cbuf).unwrap();

        // Calculate chunk index
        chunk_index = crc_idx(chunk_index) ^ slot;
        let il = chunk_index as u8;
        let ih = (chunk_index >> 8) as u8;

        // Calculate chunk checksum
        let mut dd = c.data.clone().to_vec();
        dd.extend_from_slice(&[il, ih]);
        let cs = CCITT.checksum(&dd);

        assert_eq!(cs, c.crc16);
        chunks.insert(chunk_index, c);
    }
    (chunks, free_chunks)
}

pub fn parse(data: &[u8]) {
    let size = data.len();
    let n_pages = size / PAGE_SIZE;
    let n_sys_pages = n_pages / 12;
    let n_data_pages = n_pages - n_sys_pages - 1;

    let max_sys_chunks = n_sys_pages * SYS_PAGE_CHUNKS;
    let n_data_chunks = n_data_pages * DATA_PAGE_CHUNKS;

    let mut data_pages = Vec::<DataPage>::new();
    let mut sys_pages = Vec::<SysPage>::new();
    let mut blank_page = 0;

    let mut free_data_chunks = 0;
    let mut free_sys_chunks = 0;
    for pos in (0..size).step_by(PAGE_SIZE) {
        let slice = &data[pos..pos + PAGE_SIZE];
        if u32::read_from_prefix(slice).unwrap() == PAGE_MAGIC {
            let header = PageHeader::read_from_prefix(slice).unwrap();

            let is_data = header.first_chunk > 0;
            if is_data {
                let (chunks, free) = parse_data_chunks(slice, header.first_chunk);
                free_data_chunks += free;
                data_pages.push(DataPage {
                    offset: pos,
                    header,
                    chunks,
                });
            } else {
                let (chunks, free) = parse_sys_chunks(slice);
                free_sys_chunks += free;
                sys_pages.push(SysPage {
                    offset: pos,
                    header,
                    chunks,
                });
            }
        } else {
            // this should occur exactly once
            assert_eq!(blank_page, 0);
            blank_page = pos;
        }
    }
    // sort by Update Sequence Number
    sys_pages.sort_by_key(|p| p.header.usn);
    data_pages.sort_by_key(|p| p.header.first_chunk);

    let n_sys_chunks = data_pages.first().unwrap().header.first_chunk;
    let mut data = Vec::<u8>::new();
    let mut chunks = Chunks::new();

    // check magic at beginning
    let mut sp0 = sys_pages.first().unwrap().clone();
    let sc0 = sp0.chunks.first_entry().unwrap();
    let magic = u32::read_from_prefix(&sc0.get().data).unwrap();
    println!("{magic:08x} == {:08x}", VOL_MAGIC);
    // NOTE: fails on Lenovo X270 and ASRock Z170
    // assert_eq!(magic, VOL_MAGIC);

    for p in sys_pages {
        if false {
            let o = p.offset;
            let h = p.header;
            println!("sys page @ 0x{o:08x} {h:02x?}");
        }
        for (i, c) in p.chunks {
            assert!(i < n_sys_chunks);
            data.extend_from_slice(&c.data);
            chunks.insert(i, c);
        }
    }
    let used_sys_bytes = data.len();

    for p in data_pages {
        for (i, c) in p.chunks {
            // duplicates are not allowed
            assert!(!chunks.contains_key(&i));
            data.extend_from_slice(&c.data);
            chunks.insert(i, c);
        }
    }

    let used_bytes = data.len();
    let used_data_bytes = used_bytes - used_sys_bytes;

    let free_data_bytes = free_data_chunks * CHUNK_DATA_SIZE;
    let free_sys_bytes = free_sys_chunks * CHUNK_DATA_SIZE;
    let free_bytes = free_sys_bytes + free_data_bytes;

    let data_bytes = used_data_bytes + free_data_bytes;
    let sys_bytes = used_sys_bytes + free_sys_bytes;

    let vh = VolHeader::read_from_prefix(&data).unwrap();
    println!("{vh:#04x?}");

    println!();
    println!(" system bytes used 0x{used_sys_bytes:06x}");
    println!("   data bytes used 0x{used_data_bytes:06x}");
    println!("  total bytes used 0x{used_bytes:06x}");
    println!();
    println!(" system bytes free 0x{free_sys_bytes:06x}");
    println!("   data bytes free 0x{free_data_bytes:06x}");
    println!("  total bytes free 0x{free_bytes:06x}");
    println!();

    println!("  total data bytes 0x{data_bytes:06x}");
    println!(" total sytem bytes 0x{sys_bytes:06x}");
    println!("       total bytes 0x{:06x}", used_bytes + free_bytes);
    println!("     expected      0x{:06x}", vh.chunk_bytes_total);
    println!();

    // let total_files_and_chunks = sh.files;
    let total_files_and_chunks = 20;
    let mut fat = Vec::<u16>::new();
    for i in 0..total_files_and_chunks as usize {
        let f = u16::read_from_prefix(&data[14 + i * 2..]).unwrap();
        fat.push(f);
    }

    if false {
        println!();
        println!("FAT");
        for f in fat.iter().take(10) {
            print!(" {f:04x?}");
        }
        println!();
        println!();
    }

    if true {
        println!("pages: {n_pages}");
        println!("  sys: {n_sys_pages}");
        println!("  data: {n_data_pages}");
        println!("  blank at 0x{blank_page:08x}");

        println!("\nchunks:");
        println!(" system chunks: {n_sys_chunks}");
        println!("max sys chunks: {max_sys_chunks}");
        println!("   data chunks: {n_data_chunks}");

        println!("\nbytes:");
        let sys_bytes = n_sys_chunks as usize * CHUNK_DATA_SIZE;
        let data_bytes = n_data_chunks * CHUNK_DATA_SIZE;
        println!(" system bytes: 0x{sys_bytes:06x}");
        println!("   data bytes: 0x{data_bytes:06x}");
        println!("  total bytes: 0x{:06x}", data_bytes + sys_bytes);
    }
}
