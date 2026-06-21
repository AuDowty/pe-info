use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod flags;
mod pe;

#[derive(Parser)]
#[command(name = "pe-info", version, about = "Inspect PE/COFF binaries")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    Headers { file: PathBuf },
    Sections { file: PathBuf },
    Imports { file: PathBuf },
    Exports { file: PathBuf },
}

fn main() -> ExitCode {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.payload().downcast_ref::<String>().map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.contains("failed printing to stdout") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Headers { file } => run(file, cli.json, headers),
        Command::Sections { file } => run(file, cli.json, sections),
        Command::Imports { file } => run(file, cli.json, imports),
        Command::Exports { file } => run(file, cli.json, exports),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run<F>(file: &PathBuf, json: bool, f: F) -> Result<(), String>
where
    F: FnOnce(&pe::Image, bool) -> Result<(), String>,
{
    let bytes = std::fs::read(file).map_err(|e| format!("read {}: {e}", file.display()))?;
    let img = pe::Image::parse(bytes)?;
    f(&img, json)
}

fn headers(img: &pe::Image, json: bool) -> Result<(), String> {
    let oh = &img.optional_header;
    let fh = &img.file_header;
    if json {
        let v = serde_json::json!({
            "file_size": img.file_size,
            "bits": if img.is_64 { 64 } else { 32 },
            "machine": flags::machine_name(fh.machine),
            "subsystem": flags::subsystem_name(oh.subsystem),
            "image_base": format!("0x{:x}", oh.image_base),
            "entry_point": format!("0x{:x}", oh.address_of_entry_point),
            "size_of_image": oh.size_of_image,
            "size_of_headers": oh.size_of_headers,
            "number_of_sections": fh.number_of_sections,
            "characteristics": flags::characteristics(fh.characteristics),
            "dll_characteristics": flags::dll_characteristics(oh.dll_characteristics),
            "data_directories": oh.data_directories.iter().map(|d| serde_json::json!({
                "virtual_address": format!("0x{:08x}", d.virtual_address),
                "size": d.size,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("file size:        {} bytes", img.file_size);
        println!("bits:             {}", if img.is_64 { 64 } else { 32 });
        println!("machine:          {}", flags::machine_name(fh.machine));
        println!("subsystem:        {}", flags::subsystem_name(oh.subsystem));
        println!("image base:       0x{:x}", oh.image_base);
        println!("entry point rva:  0x{:x}", oh.address_of_entry_point);
        println!("size of image:    0x{:x}", oh.size_of_image);
        println!("size of headers:  0x{:x}", oh.size_of_headers);
        println!("sections:         {}", fh.number_of_sections);
        let c = flags::characteristics(fh.characteristics);
        if !c.is_empty() {
            println!("characteristics:  {}", c.join(" "));
        }
        let dc = flags::dll_characteristics(oh.dll_characteristics);
        if !dc.is_empty() {
            println!("dll flags:        {}", dc.join(" "));
        }
    }
    Ok(())
}

fn sections(img: &pe::Image, json: bool) -> Result<(), String> {
    if json {
        let arr: Vec<_> = img
            .sections
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "virtual_address": format!("0x{:08x}", s.virtual_address),
                    "virtual_size": s.virtual_size,
                    "raw_address": format!("0x{:08x}", s.raw_address),
                    "raw_size": s.raw_size,
                    "characteristics": flags::section_characteristics(s.characteristics),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        println!(
            "{:<10} {:<12} {:>10}  {:<12} {:>10}  FLAGS",
            "NAME", "VADDR", "VSIZE", "RAWADDR", "RAWSIZE"
        );
        for s in &img.sections {
            println!(
                "{:<10} 0x{:08x}   {:>10}  0x{:08x}  {:>10}  {}",
                s.name,
                s.virtual_address,
                s.virtual_size,
                s.raw_address,
                s.raw_size,
                flags::section_characteristics(s.characteristics).join(" ")
            );
        }
    }
    Ok(())
}

fn imports(img: &pe::Image, json: bool) -> Result<(), String> {
    let imps = img.imports()?;
    if json {
        let arr: Vec<_> = imps
            .iter()
            .map(|i| {
                serde_json::json!({
                    "dll": i.dll,
                    "functions": i.functions.iter().map(|f| match f {
                        pe::ImportFn::Named(n) => serde_json::Value::String(n.clone()),
                        pe::ImportFn::Ordinal(o) => serde_json::json!({ "ordinal": o }),
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        if imps.is_empty() {
            println!("(no imports)");
            return Ok(());
        }
        for i in &imps {
            println!("{} ({} functions)", i.dll, i.functions.len());
            for f in &i.functions {
                match f {
                    pe::ImportFn::Named(n) => println!("  {n}"),
                    pe::ImportFn::Ordinal(o) => println!("  #{o}"),
                }
            }
        }
    }
    Ok(())
}

fn exports(img: &pe::Image, json: bool) -> Result<(), String> {
    let exps = img.exports()?;
    if json {
        let arr: Vec<_> = exps
            .iter()
            .map(|e| {
                serde_json::json!({
                    "ordinal": e.ordinal,
                    "rva": format!("0x{:08x}", e.rva),
                    "name": e.name,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        if exps.is_empty() {
            println!("(no exports)");
            return Ok(());
        }
        println!("{:>7}  {:<12}  NAME", "ORDINAL", "RVA");
        for e in &exps {
            println!("{:>7}  0x{:08x}  {}", e.ordinal, e.rva, e.name);
        }
    }
    Ok(())
}
