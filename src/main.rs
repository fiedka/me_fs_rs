use clap::Parser;
use me_fs_rs::{parse, CodePartitionDirectory, FPTEntry, ME_FPT};
use std::fs;
use std::io;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File to read
    #[arg(short, long)]
    file: String,
}

fn print_directories(cpds: &Vec<CodePartitionDirectory>) {
    for cpd in cpds {
        println!();
        let CodePartitionDirectory { header, entries } = cpd;
        let pname = std::str::from_utf8(&header.part_name).unwrap();
        let checksum = header.version_or_checksum;
        println!("{pname}  {checksum:08x}");
        println!("  file name        offset    size        compression flags");
        for e in entries {
            let o = e.offset;
            let s = e.size;
            let f = e.compression_flag;
            if let Ok(n) = std::str::from_utf8(&e.name) {
                let n = n.trim_end_matches(char::from(0));
                println!("  {n:13} @ {o:08x}:{s:08x}    {f:032}");
            }
        }
    }
}

fn print_fpt_entries(entries: &Vec<FPTEntry>) {
    println!("  name     offset     size      type   notes");
    for e in entries {
        let o = e.offset as usize;
        let s = e.size as usize;

        let name = std::str::from_utf8(&e.name).unwrap();
        let name = name.trim_end_matches(char::from(0));

        let (part_type, full_name) = me_fs_rs::get_part_info(name);
        let part_info = format!("{part_type:?}: {full_name}");
        let name_offset_size = format!("{name:>4} @ 0x{o:08x}:0x{s:08x}");

        println!("- {name_offset_size}  {part_info}");
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;
    println!("Scanning {file} for ME FPT");

    let data = fs::read(file).unwrap();

    if let Ok(fpt) = parse(&data) {
        let ME_FPT {
            header,
            entries,
            directories,
        } = fpt;
        println!("\n{header:#0x?}");
        println!("\nPartitions:");
        print_fpt_entries(&entries);
        println!("\nDirectories:");
        print_directories(&directories);
    }
    Ok(())
}
