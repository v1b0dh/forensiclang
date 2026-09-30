//! CARVE Compiler Driver — `carvec`
//!
//! Usage:
//!   carvec <source.crv>               Parse and dump AST as JSON
//!   carvec <source.crv> --ast         Parse and dump AST as JSON
//!   carvec <source.crv> --check       Parse-only (syntax check)

mod ast;
mod parser;

use clap::Parser as ClapParser;
use std::fs;
use std::process;

#[derive(ClapParser, Debug)]
#[command(
    name = "carvec",
    about = "CARVE forensic scripting language compiler",
    version
)]
struct Cli {
    /// Path to .crv or .jky source file
    source: String,

    /// Dump the AST as JSON
    #[arg(long)]
    ast: bool,

    /// Parse-only syntax check (exit 0 = valid, exit 1 = errors)
    #[arg(long)]
    check: bool,
}

fn main() {
    let cli = Cli::parse();

    // Read source file
    let source = match fs::read_to_string(&cli.source) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[carvec] ERROR: Cannot read '{}': {}", cli.source, e);
            process::exit(1);
        }
    };

    // Parse
    let program = match parser::parse(&source) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[carvec] {}", e);
            process::exit(1);
        }
    };

    if cli.check {
        println!(
            "[carvec] OK: {} statement(s) parsed from '{}'",
            program.statements.len(),
            cli.source
        );
        return;
    }

    if cli.ast {
        match serde_json::to_string_pretty(&program) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("[carvec] JSON serialization error: {e}");
                process::exit(1);
            }
        }
        return;
    }

    // Default: parse + summary
    println!("[carvec] Parsed '{}' → {} statement(s)", cli.source, program.statements.len());
    for (i, stmt) in program.statements.iter().enumerate() {
        let kind = match stmt {
            ast::Statement::Collect(c) => format!("collect {:?}", c.target),
            ast::Statement::Scan(s) => format!("scan {:?}", s.target),
            ast::Statement::Carve(c) => format!("carve disk from drive {} (types: {:?})", c.drive, c.target_types),
            ast::Statement::Erase(e) => format!("erase {:?} {} (method: {:?})", e.target_type, e.target_path, e.method),
            ast::Statement::Analyze(a) => format!("analyze {}", a.target),
            ast::Statement::Timeline(t) => format!("timeline host {}", t.host),
            ast::Statement::Correlate(c) => format!("correlate {} with {}", c.data, c.ioc_list),
            ast::Statement::Report(r) => format!("report {} as {}", r.target, r.filename),
            ast::Statement::Assign(a) => format!("assign {}", a.name),
            ast::Statement::Call(c) => format!("call {}({} args)", c.callee, c.args.len()),
            ast::Statement::If(_) => "if".to_string(),
            ast::Statement::For(f) => format!("for {} each {}", f.var, f.iterable),
            ast::Statement::FuncDecl(f) => format!("function {}({})", f.name, f.params.join(", ")),
        };
        println!("  [{:>2}] {kind}", i + 1);
    }

    // TODO: Phase 2.5+ — LLVM IR codegen via inkwell
    println!("\n[carvec] Note: LLVM IR codegen not yet implemented in Rust compiler.");
    println!("[carvec] Use the Python compiler (compiler/carvec.py) for full compilation.");
}
