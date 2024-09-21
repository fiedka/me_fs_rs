use std::mem;
use zerocopy::FromBytes;

pub mod cpd;
pub mod fpt;
pub mod mfs;

pub use fpt::ME_FPT;

// *CCITT CRC-16 is calculated from the chunk data and the 16-bit (2-byte) chunk index
// https://srecord.sourceforge.net/crc16-ccitt.html
pub const CCITT: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

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

fn parse_mfs(data: &[u8], base: usize, e: &fpt::FPTEntry) {
    let o = base + e.offset as usize;
    let s = e.size as usize;
    let end = o + s;
    let pages = s / mfs::MFS_PAGE_SIZE;
    let n_sys_pages = pages / 12;
    let n_data_pages = pages - n_sys_pages - 1;

    let n_sys_chunks = n_sys_pages * mfs::MFS_SYS_PAGE_CHUNKS;
    let n_data_chunks = n_data_pages * mfs::MFS_DATA_PAGE_CHUNKS;

    let mut data_pages = Vec::<mfs::MFSDataPage>::new();
    let mut sys_pages = Vec::<mfs::MFSSysPage>::new();
    let mut blank_page = 0;

    // NOTE: We cannot use MFS_PAGE_HEADER_SIZE here.
    const SLOTS_OFFSET: usize = 18;
    const SYS_CHUNKS_OFFSET: usize = SLOTS_OFFSET + 2 * mfs::MFS_SYS_PAGE_SLOTS;
    const DATA_CHUNKS_OFFSET: usize = SLOTS_OFFSET + 2 * mfs::MFS_DATA_PAGE_SLOTS;

    let mut free_data_chunks = 0;
    let mut free_sys_chunks = 0;
    for pos in (o..end).step_by(mfs::MFS_PAGE_SIZE) {
        let buf = &data[pos..pos + 4];
        let magic = u32::read_from_prefix(buf).unwrap();
        if magic == mfs::MFS_MAGIC {
            let p = pos + mfs::MFS_PAGE_HEADER_SIZE;
            let c = &data[pos..p];
            let header = mfs::MFSPageHeader::read_from_prefix(c).unwrap();

            let is_data = header.first_chunk > 0;
            if is_data {
                let slots_offset = pos + SLOTS_OFFSET;
                let chunks_offset = pos + DATA_CHUNKS_OFFSET;

                let mut chunks = mfs::Chunks::new();

                for chunk_pos in 0..mfs::MFS_DATA_PAGE_SLOTS {
                    let o = slots_offset + chunk_pos;
                    let s = u8::read_from_prefix(&data[o..]).unwrap();

                    // free chunk
                    if s == 0xff {
                        free_data_chunks += 1;
                        continue;
                    }

                    let chunk_index = header.first_chunk + chunk_pos as u16;

                    // Parse the chunk
                    let coff = chunks_offset + chunk_pos * mfs::MFS_CHUNK_SIZE;
                    let cbuf = &data[coff..coff + mfs::MFS_CHUNK_SIZE];
                    let c = mfs::MFSChunk::read_from_prefix(cbuf).unwrap();

                    chunks.insert(chunk_index, c);
                }

                let page = mfs::MFSDataPage {
                    offset: pos,
                    header,
                    chunks,
                };
                data_pages.push(page);
            } else {
                let slots_offset = pos + SLOTS_OFFSET;
                let chunks_offset = pos + SYS_CHUNKS_OFFSET;

                let mut chunks = mfs::Chunks::new();
                let mut chunk_index = 0;

                for chunk_pos in 0..mfs::MFS_SYS_PAGE_SLOTS {
                    let o = slots_offset + 2 * chunk_pos;
                    let s = u16::read_from_prefix(&data[o..]).unwrap();

                    // Last chunk is marked
                    if s == mfs::MFS_SLOT_LAST {
                        let remaining = mfs::MFS_SYS_PAGE_CHUNKS - chunk_pos;
                        free_sys_chunks += remaining;
                        break;
                    }

                    // Parse the chunk
                    let coff = chunks_offset + chunk_pos * mfs::MFS_CHUNK_SIZE;
                    let cbuf = &data[coff..coff + mfs::MFS_CHUNK_SIZE];
                    let c = mfs::MFSChunk::read_from_prefix(cbuf).unwrap();

                    // Calculate chunk index
                    chunk_index = crc_idx(chunk_index) ^ s;
                    let il = chunk_index as u8;
                    let ih = (chunk_index >> 8) as u8;

                    // Calculate chunk checksum
                    let mut dd = c.data.clone().to_vec();
                    dd.extend_from_slice(&[il, ih]);
                    let cs = CCITT.checksum(&dd);

                    assert_eq!(cs, c.crc16);
                    chunks.insert(s, c);
                }

                let page = mfs::MFSSysPage {
                    offset: pos,
                    header,
                    chunks,
                };

                sys_pages.push(page);
            }
        } else {
            // this should occur exactly once
            blank_page = pos;
        }
    }
    // sort by Update Sequence Number
    data_pages.sort_by_key(|p| p.header.first_chunk);
    sys_pages.sort_by_key(|p| p.header.usn);

    // check magic at beginning
    let ps = &mut sys_pages.clone();
    let e0 = ps[0].chunks.first_entry().unwrap();
    let c0 = e0.get();
    let magic = u32::read_from_prefix(&c0.data).unwrap();
    println!("{magic:08x} == {:08x}", mfs::XXX_MAGIC);
    // NOTE: fails on Lenovo X270 and ASRock Z170
    // assert_eq!(magic, mfs::XXX_MAGIC);

    let sh = mfs::MFSSysHeader::read_from_prefix(&c0.data).unwrap();
    println!("{sh:#04x?}");

    let mut data = Vec::<u8>::new();
    for p in sys_pages {
        let o = p.offset;
        let h = p.header;
        println!("sys page @ 0x{o:08x} {h:04x?}");

        for (_, c) in p.chunks {
            data.extend_from_slice(&c.data);
        }
    }
    let used_sys_bytes = data.len();
    for p in data_pages {
        for (_, c) in p.chunks {
            data.extend_from_slice(&c.data);
        }
    }
    let used_bytes = data.len();
    let used_data_bytes = used_bytes - used_sys_bytes;

    let free_data_bytes = free_data_chunks * mfs::MFS_CHUNK_DATA_SIZE;
    let free_sys_bytes = free_sys_chunks * mfs::MFS_CHUNK_DATA_SIZE;
    let free_bytes = free_sys_bytes + free_data_bytes;

    let data_bytes = used_data_bytes + free_data_bytes;
    let sys_bytes = used_sys_bytes + free_sys_bytes;

    println!();
    println!(" system bytes used 0x{used_sys_bytes:08x}");
    println!("   data bytes used 0x{used_data_bytes:08x}");
    println!("  total bytes used 0x{used_bytes:08x}");
    println!();
    println!(" system bytes free 0x{free_sys_bytes:08x}");
    println!("   data bytes free 0x{free_data_bytes:08x}");
    println!("  total bytes free 0x{free_bytes:08x}");
    println!();

    println!("  total data bytes 0x{data_bytes:08x}");
    println!(" total sytem bytes 0x{sys_bytes:08x}");
    println!("       total bytes 0x{:08x}", used_bytes + free_bytes);
    println!("     expected      0x{:08x}", sh.chunk_bytes_total);
    println!();

    // let total_files_and_chunks = sh.files;
    let total_files_and_chunks = 20;
    let mut fat = Vec::<u16>::new();
    for i in 0..total_files_and_chunks as usize {
        let f = u16::read_from_prefix(&c0.data[14 + i * 2..]).unwrap();
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
        println!("pages: {pages}");
        println!("  sys: {n_sys_pages}");
        println!("  data: {n_data_pages}");
        println!("  blank at 0x{blank_page:08x}");
        println!("data chunks: {n_data_chunks}");

        println!("\nbytes:");
        let data_bytes = n_data_chunks * mfs::MFS_CHUNK_DATA_SIZE;
        let sys_bytes = n_sys_chunks * mfs::MFS_CHUNK_DATA_SIZE;
        println!("   data bytes: 0x{data_bytes:08x}");
        println!(" system bytes: 0x{sys_bytes:08x}");
        println!("  total bytes: 0{:08x}", data_bytes + sys_bytes);
    }
}

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let mut base = 0;
    while base + 16 + mem::size_of::<fpt::FPT>() <= data.len() {
        // first 16 bytes are potentially other stuff
        let o = base + 16;
        let buf = &data[o..o + 32];
        if let Ok(s) = std::str::from_utf8(&buf[..8]) {
            if s.starts_with(fpt::FPT_MAGIC) {
                let fpt = fpt::FPT::read_from_prefix(&data[o..]).unwrap();
                let mut entries = Vec::<fpt::FPTEntry>::new();
                for e in 0..fpt.entries as usize {
                    // NOTE: Skip $FPT itself
                    let pos = o + 32 + e * 32;
                    let entry = fpt::FPTEntry::read_from_prefix(&data[pos..]).unwrap();
                    entries.push(entry);
                }

                // realign base
                if base % 0x1000 != 0 {
                    println!("realign");
                    base = o;
                }

                let mut directories = Vec::<cpd::CodePartitionDirectory>::new();
                for e in &entries {
                    let n = std::str::from_utf8(&e.name).unwrap();
                    // some names are shorter than 4 bytes and padded with 0x0
                    let n = n.trim_end_matches(char::from(0));

                    if n == "FTPR" || n == "NFTP" {
                        let o = base + e.offset as usize;
                        let s = e.size as usize;

                        let buf = &data[o..o + 4];
                        if let Ok(sig) = std::str::from_utf8(buf) {
                            if sig == cpd::CPD_MAGIC {
                                let cpd = cpd::parse_cpd(&data[o..o + s]).unwrap();
                                directories.push(cpd);
                            }
                        }
                    }

                    if n == "MFS" {
                        parse_mfs(data, base, e);
                    }
                }

                let me_fpt = ME_FPT {
                    base,
                    header: fpt,
                    entries,
                    directories,
                };
                return Ok(me_fpt);
            }
        }
        base += 16;
    }
    Err("No $FPT :(".to_string())
}
