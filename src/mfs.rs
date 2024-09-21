use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

// see https://live.ructf.org/intel_me.pdf slide 35
const PAGE_MAGIC: u32 = 0xaa55_7887;

const PAGE_SIZE: usize = 0x2000;

// NOTE: We cannot use std::mem::size_of::<PageHeader>() here because it is
// larger than the underlying data.
const SLOTS_OFFSET: usize = 18;
// NOTE: System and data pages have different chunk counts and different slot sizes!
const SYS_CHUNKS_OFFSET: usize = SLOTS_OFFSET + 2 * SYS_PAGE_SLOTS;
const DATA_CHUNKS_OFFSET: usize = SLOTS_OFFSET + DATA_PAGE_SLOTS;

const CHUNK_DATA_SIZE: usize = 0x40;
// + 2 bytes checksum
const CHUNK_SIZE: usize = CHUNK_DATA_SIZE + 2;

const SYS_PAGE_CHUNKS: usize = 120;
const SYS_PAGE_SLOTS: usize = SYS_PAGE_CHUNKS + 1;

const DATA_PAGE_CHUNKS: usize = 122;
const DATA_PAGE_SLOTS: usize = DATA_PAGE_CHUNKS;

const SLOT_UNUSED: u16 = 0xffff;
const SLOT_LAST: u16 = 0x7fff;

const VOL_MAGIC: u32 = 0x724F_6201;
// NOTE: We cannot use std::mem::size_of::<VolHeader>() here because it is
// larger than the underlying data.
const VOL_HEADER_SIZE: usize = 14;

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

const DEBUG_FAT: bool = true;
const VERBOSE: bool = false;

fn parse_sys_chunks(data: &[u8]) -> (Chunks, usize, usize) {
    let mut dup_chunks = 0;
    let mut free_chunks = 0;
    let mut chunks = Chunks::new();
    let mut chunk_index = 0;

    for chunk_pos in 0..SYS_PAGE_SLOTS {
        let o = SLOTS_OFFSET + 2 * chunk_pos;
        // aka axIdx in PT code
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
        // Calculate chunk checksum
        let mut dd = c.data.clone().to_vec();
        dd.extend_from_slice(&chunk_index.to_le_bytes());
        let cs = CCITT.checksum(&dd);

        assert_eq!(cs, c.crc16);
        // XXX: In reality, chunk index is not unique, so it's not the index?
        if chunks.contains_key(&chunk_index) {
            dup_chunks += 1;
            if VERBOSE {
                println!("dup chunk {chunk_pos:03}: {slot:04x} {chunk_index:04x}");
            }
        }
        chunks.insert(chunk_index, c);
    }
    (chunks, free_chunks, dup_chunks)
}

fn get_file<'a>(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    file_index: usize,
) -> Result<Vec<u8>, &'a str> {
    let mut i_node = fat[file_index];
    println!("  chunks: {}, fat size: {}", chunks.len(), fat.len());
    println!("  file {file_index:04} iNode {i_node:04x}");
    if i_node == 0xffff {
        return Err("empty file");
    }
    if i_node == 0x0000 {
        return Err("no file");
    }

    let mut data = Vec::<u8>::new();
    loop {
        assert!(i_node >= n_files);
        let ci = i_node + n_sys_chunks - n_files;
        let c = chunks[&ci];
        i_node = fat[i_node as usize];
        println!("  next {i_node}");
        // For the last chunk, i_node is the number of remaining bytes
        if i_node > 0 && i_node as usize <= CHUNK_SIZE {
            data.extend_from_slice(&c.data[..i_node as usize]);
            break;
        }
        data.extend_from_slice(&c.data);
        // println!("{data:02x?}");
    }
    Ok(data)
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
    let mut dup_sys_chunks = 0;
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
                let (chunks, free, dups) = parse_sys_chunks(slice);
                free_sys_chunks += free;
                dup_sys_chunks += dups;
                let l = chunks.len();
                println!("sys page @ 0x{pos:06x}: usn {:02x?}", header.usn);
                println!("  {l} chunks, {dups} duplicates, {free} free");
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

    // The first data chunk comes right after the last system chunk.
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

    let mut real_n_sys_chunks = 0;
    for p in sys_pages {
        for (i, c) in p.chunks {
            assert!(i < n_sys_chunks);
            if chunks.contains_key(&i) {
                dup_sys_chunks += 1;
            } else {
                real_n_sys_chunks += 1;
            }
            chunks.insert(i, c);
        }
    }
    for (_, c) in &chunks {
        data.extend_from_slice(&c.data);
    }

    // real_n_sys_chunks += dup_sys_chunks;
    let used_sys_bytes = data.len() + dup_sys_chunks * CHUNK_SIZE;

    for (pi, p) in data_pages.iter().enumerate() {
        let first_chunk_expected = n_sys_chunks as usize + pi * DATA_PAGE_CHUNKS;
        assert_eq!(p.header.first_chunk as usize, first_chunk_expected);
        for (ci, c) in &p.chunks {
            // duplicates are not allowed
            assert!(!chunks.contains_key(ci));
            data.extend_from_slice(&c.data);
            chunks.insert(*ci, *c);
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

    println!(" sys chunks expected: {n_sys_chunks}");
    println!("          really got: {real_n_sys_chunks}");
    println!("          duplicates: {dup_sys_chunks}");
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

    let total_files_and_chunks = vh.files as usize + n_data_chunks;
    println!("total files and chunks: {total_files_and_chunks}");
    let mut fat = Vec::<u16>::new();
    let d = &data[VOL_HEADER_SIZE..VOL_HEADER_SIZE + total_files_and_chunks * 2];
    // two bytes each
    for p in (0..total_files_and_chunks).step_by(2) {
        let f = u16::read_from(&d[p..p + 2]).unwrap();
        fat.push(f);
    }

    if DEBUG_FAT {
        println!();
        println!("FAT");
        for (i, f) in fat.iter().enumerate() {
            if i == vh.files as usize {
                println!();
            }
            if i % 64 == 0 {
                println!();
            }
            if i % 16 == 0 {
                print!("\n{i:04x}: ");
            }
            print!("{f:04x} ");
        }
        println!();
        println!();
    }

    if true {
        println!("size: {size}");
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

    let file_index = 0x6;
    if let Ok(f) = get_file(&chunks, n_sys_chunks, &fat, vh.files, file_index) {
        println!("  file {file_index:04} size: {}", f.len());
        // println!("{f:02x?}");
    }
}
