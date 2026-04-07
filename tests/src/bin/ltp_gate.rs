use std::env;
use std::path::PathBuf;

use tidemark_kernel_tests::ltp_gate;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let kernel_root = parse_kernel_root(&mut args)?;
    let Some(cmd) = args.first().cloned() else {
        return Err(usage());
    };

    match cmd.as_str() {
        "case" => {
            let Some(case_name) = args.get(1).cloned() else {
                return Err(usage());
            };
            if args.len() != 2 {
                return Err(usage());
            }
            let report = ltp_gate::build_report(&kernel_root, &case_name)?;
            ltp_gate::print_report(&report);
            Ok(())
        }
        "guard" => {
            let Some(case_name) = args.get(1).cloned() else {
                return Err(usage());
            };
            if args.len() != 2 {
                return Err(usage());
            }
            let report = ltp_gate::build_report(&kernel_root, &case_name)?;
            ltp_gate::print_report(&report);
            if ltp_gate::rerun_allowed(&report) {
                Ok(())
            } else {
                std::process::exit(2);
            }
        }
        "batch-implemented" => {
            if args.len() != 1 {
                return Err(usage());
            }
            let reports = ltp_gate::implemented_case_reports(&kernel_root)?;
            ltp_gate::print_batch_report(&reports);
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn parse_kernel_root(args: &mut Vec<String>) -> Result<PathBuf, String> {
    let mut root: Option<PathBuf> = None;
    while !args.is_empty() {
        if args[0] != "--kernel-root" {
            break;
        }
        if args.len() < 2 {
            return Err("missing value for --kernel-root".to_string());
        }
        root = Some(PathBuf::from(args[1].clone()));
        args.drain(0..=1);
    }

    ltp_gate::resolve_kernel_root(root.as_deref())
}

fn usage() -> String {
    "usage: cargo run -p tidemark-kernel-tests --bin ltp_gate -- [--kernel-root <path>] <case|guard> <ltp_case_name>\n       cargo run -p tidemark-kernel-tests --bin ltp_gate -- [--kernel-root <path>] batch-implemented"
        .to_string()
}
