use std::process::exit;

use libbpf_rs::query;
use nix::unistd::Uid;
use structopt::StructOpt;

/// Query the system about BPF-related information
#[derive(Debug, StructOpt)]
enum Command {
    /// Display information about progs
    Prog,
    /// Display information about maps
    Map,
    /// Display information about BTF
    Btf,
}

fn prog() {
    for prog in query::ProgInfoIter::default() {
        match prog {
            Ok(p) => {
                println!(
                    "name={:<16} type={:<15} run_count={:<2} runtime_ns={}",
                    p.name,
                    p.ty.to_string(),
                    p.run_cnt,
                    p.run_time_ns
                );
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn map() {
    for map in query::MapInfoIter::default() {
        match map {
            Ok(m) => println!("name={:<16} type={}", m.name, m.ty.to_string(),),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn btf() {
    for btf in query::BtfInfoIter::default() {
        match btf {
            Ok(b) => println!("id={:4} size={}", b.id, b.btf_size),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("Must run as root");
        exit(1);
    }

    let opts = Command::from_args();

    match opts {
        Command::Prog => prog(),
        Command::Map => map(),
        Command::Btf => btf(),
    };
}
