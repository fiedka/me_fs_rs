use clap::Parser;
use me_fs_rs::{cpd::CodePartitionDirectory, fpt::FPTEntry, parse, ME_FPT};
use std::fs;
use std::io;

/// Print Intel (CS)ME FPT information
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Print header data
    #[arg(required = false, short, long)]
    print: bool,

    /// Print verbosely, including partitions and directories
    #[arg(required = false, short, long)]
    verbose: bool,

    /// File to read
    #[arg(index = 1)]
    file: String,
}

fn print_directories(dirs: &Vec<CodePartitionDirectory>, data: &[u8]) {
    for d in dirs {
        println!();
        let checksum = d.header.version_or_checksum;
        println!("{} checksum or version: {checksum:08x}", d.name);
        let o = d.offset;
        let manifest_name = format!("{}.man", d.name);
        match d.manifest() {
            Ok(m) => println!("{m}"),
            Err(e) => println!("{e}"),
        }

        println!("  file name        offset    end       size           compression flags");
        let mut entries = d.entries.clone();
        entries.sort_by_key(|e| e.offset);
        for e in entries {
            let o = e.offset;
            let s = e.size;
            let end = o + s;
            let f = e.compression_flag;
            if let Ok(n) = std::str::from_utf8(&e.name) {
                let n = n.trim_end_matches(char::from(0));
                println!("  {n:13} @ 0x{o:06x}:0x{end:06x} (0x{s:06x}) {f:032b}");
            }
        }
    }
}

fn print_fpt_entries(entries: &Vec<FPTEntry>) {
    println!("  name     offset     end         size       type  notes");
    let mut entries = entries.clone();
    entries.sort_by_key(|e| e.offset);
    for e in entries {
        let o = e.offset as usize;
        let s = e.size as usize;
        let end = o + s;

        let name = std::str::from_utf8(&e.name).unwrap();
        let name = name.trim_end_matches(char::from(0));

        let (part_type, full_name) = me_fs_rs::fpt::get_part_info(name);
        let part_info = format!("{part_type:?}: {full_name}");
        let name_offset_end_size = format!("{name:>4} @ 0x{o:08x}:0x{end:08x} (0x{s:08x})");

        println!("- {name_offset_end_size}  {part_info}");
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;
    println!("Scanning {file} for ME FPT");

    let data = fs::read(file).unwrap();

    match parse(&data) {
        Ok(fpt) => {
            let ME_FPT {
                base,
                header,
                entries,
                directories,
            } = fpt;
            if args.verbose {
                println!("\nFound at 0x{base:08x}: {header:#0x?}");
            } else if args.print {
                println!("\nFound at 0x{base:08x}: Version {}", header.header_ver);
            }
            if args.print || args.verbose {
                println!("\nPartitions:");
                print_fpt_entries(&entries);
            }
            if args.verbose {
                println!("\nDirectories:");
                print_directories(&directories, &data);
            }
        }
        Err(e) => {
            println!("Error: {e}");
        }
    }
    Ok(())
}
