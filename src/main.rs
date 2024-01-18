use clap::Parser;
use me_fs_rs::parse;
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

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;

    if let Ok(data) = fs::read(&file) {
        println!("Scanning {} for ME FPT", &file);
        if let Ok(fpt) = parse(&data) {
            println!("{fpt:#?}");
        }
    }
    else {
        println!("Invalid file: {}", &file); 
    }

    Ok(())
}
