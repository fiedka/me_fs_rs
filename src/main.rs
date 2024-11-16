use clap::Parser;
use me_fs_rs::{
    cpd::CodePartitionDirectory, fpt::FPTEntry, gen2::Directory as Gen2Dir, parse, ME_FPT,
};
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

fn print_gen2_dirs(dirs: &Vec<Gen2Dir>) {
    for dir in dirs {
        println!("{dir}");
        for e in &dir.entries {
            let pos = dir.offset + e.offset as usize;
            /*
            let sig =
                u32::read_from_prefix(&data[pos..pos + 4]).unwrap();
            let kind = match sig {
                SIG_LUT => "LLUT",
                SIG_LZMA => "LZMA",
                _ => {
                    dump48(&data[pos..]);
                    "unknown"
                }
            };
            */
            let kind = "...";
            let t = e.compression_type();
            let b = e.bin_map();
            println!(" - {e}    {pos:08x} {t:?} ({kind})\n     {b}");
        }
        println!();
    }
}

fn print_directories(dirs: &Vec<CodePartitionDirectory>) {
    for d in dirs {
        println!();
        let checksum = d.header.version_or_checksum;
        let o = d.offset;
        println!("{} @ {o:08x}, checksum or version: {checksum:08x}", d.name);
        match d.manifest() {
            Ok(m) => println!("{m}"),
            Err(e) => println!("{e}"),
        }

        println!("  file name        offset    end       size           compression flags");
        let mut entries = d.entries.clone();
        entries.sort_by_key(|e| e.offset);
        for e in entries {
            println!("  {e}");
        }
    }
}

fn print_fpt_entries(entries: &Vec<FPTEntry>) {
    println!("  name     offset     end         size       type  notes");
    let mut entries = entries.clone();
    entries.sort_by_key(|e| e.offset);
    for e in entries {
        println!("- {e}");
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
                gen2dirs,
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
                print_directories(&directories);
                print_gen2_dirs(&gen2dirs);
            }
        }
        Err(e) => {
            println!("Error: {e}");
        }
    }
    Ok(())
}
