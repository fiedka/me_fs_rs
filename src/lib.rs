use serde::{Deserialize, Serialize};
use std::mem;
use zerocopy::FromBytes;

pub mod cpd;
pub mod fpt;
pub mod mfs;

pub use fpt::ME_FPT;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PartitionType {
    Code,
    Data,
    None,
}

// see https://troopers.de/downloads/troopers17/TR17_ME11_Static.pdf
pub fn get_part_info(n: &str) -> (PartitionType, &str) {
    match n {
        "FTPR" => (PartitionType::Code, "Main code partition"),
        "FTUP" => (PartitionType::Code, "[NFTP]+[WCOD]+[LOCL]"),
        "DLMP" => (PartitionType::Code, "IDLM partition"),
        "PSVN" => (PartitionType::Data, "Secure Version Number"),
        "IVBP" => (PartitionType::Data, "IV + Bring Up cache"),
        "MFS" => (PartitionType::Data, "ME Flash File System"),
        "NFTP" => (PartitionType::Code, "Additional code"),
        "ROMB" => (PartitionType::Code, "ROM Bypass"),
        "WCOD" => (PartitionType::Code, "WLAN uCode"),
        "LOCL" => (PartitionType::Code, "AMT Localization"),
        "FLOG" => (PartitionType::Data, "Flash Log"),
        "UTOK" => (PartitionType::Data, "Debug Unlock Token"),
        "ISHC" => (PartitionType::Code, "Integrated Sensors Hub"),
        _ => (PartitionType::None, ""),
    }
}

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let mut b = 0;

    while b + 16 + mem::size_of::<fpt::FPT>() <= data.len() {
        // first 16 bytes are potentially other stuff
        let o = b + 16;
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
                if b % 0x1000 != 0 {
                    println!("realign");
                    b = o;
                }

                let mut directories = Vec::<cpd::CodePartitionDirectory>::new();
                for e in &entries {
                    let n = std::str::from_utf8(&e.name).unwrap();
                    // some names are shorter than 4 bytes and padded with 0x0
                    let n = n.trim_end_matches(char::from(0));

                    if n == "FTPR" || n == "NFTP" {
                        let o = b + e.offset as usize;
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
                        let o = b + e.offset as usize;
                        let s = e.size as usize;
                        let end = o + s;
                        let pages = s / mfs::MFS_PAGE_SIZE;
                        let n_sys_pages = pages / 12;
                        let n_data_pages = pages - n_sys_pages - 1;

                        let mut data_pages = Vec::<mfs::MFSDataPage>::new();
                        let mut sys_pages = Vec::<mfs::MFSSysPage>::new();
                        let mut other_pages = Vec::<usize>::new();
                        for pos in (o..end).step_by(mfs::MFS_PAGE_SIZE) {
                            let buf = &data[pos..pos + 4];
                            let magic = u32::read_from_prefix(buf).unwrap();
                            if magic == mfs::MFS_MAGIC {
                                let p = pos + mfs::MFS_PAGE_HEADER_SIZE;
                                let c = &data[pos..p];
                                let header = mfs::MFSPageHeader::read_from_prefix(c).unwrap();

                                let is_data = header.first_chunk > 0;
                                let slots = if is_data {
                                    mfs::MFS_DATA_PAGE_SLOTS
                                } else {
                                    mfs::MFS_SYS_PAGE_SLOTS
                                };

                                let mut last_slot = 0;
                                for slot in 0..slots {
                                    let s = u16::read_from_prefix(&data[p + slot * 2..]).unwrap();
                                    if s == mfs::MFS_SLOT_LAST {
                                        last_slot = slot;
                                    }
                                }

                                if is_data {
                                    let page = mfs::MFSDataPage {
                                        offset: pos,
                                        header,
                                        // a_free: [0u8; 122],
                                    };
                                    data_pages.push(page);
                                } else {
                                    let busy_slot = u16::read_from_prefix(&data[p..]).unwrap();
                                    let next_slot = u16::read_from_prefix(&data[p + 2..]).unwrap();
                                    let page = mfs::MFSSysPage {
                                        offset: pos,
                                        header,
                                        busy_slot,
                                        next_slot,
                                        last_slot,
                                    };
                                    sys_pages.push(page);
                                }
                            } else {
                                other_pages.push(pos);
                            }
                        }
                        // sort by Update Sequence Number
                        data_pages.sort_by_key(|p| p.header.usn);
                        for p in data_pages {
                            println!("{p:#02x?}")
                        }
                        for p in sys_pages {
                            println!("{p:#02x?}")
                        }
                        println!("pages: {pages} sys: {n_sys_pages} data: {n_data_pages}");
                        println!("no MFS page at {other_pages:08x?}");
                    }
                }

                let me_fpt = ME_FPT {
                    base: b,
                    header: fpt,
                    entries,
                    directories,
                };
                return Ok(me_fpt);
            }
        }
        b += 16;
    }
    Err("No $FPT :(".to_string())
}
