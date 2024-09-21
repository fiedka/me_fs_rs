use std::mem;
use zerocopy::FromBytes;

pub mod cpd;
pub mod fpt;
pub mod mfs;

pub use fpt::ME_FPT;

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
                        mfs::parse(data, base, e);
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
