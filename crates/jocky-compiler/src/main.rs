//! JOCKY Compiler Driver — `jockc`
//!
//! Usage:
//!   jockc <source.jky>               Parse and dump AST as JSON
//!   jockc <source.jky> --ast         Parse and dump AST as JSON
//!   jockc <source.jky> --check       Parse-only (syntax check)

mod ast;
mod parser;

use clap::Parser as ClapParser;
use std::fs;
use std::process;

#[derive(ClapParser, Debug)]
#[command(
    name = "jockc",
    about = "JOCKY forensic scripting language compiler",
    version
)]
struct Cli {
    /// Path to .jky source file
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
            eprintln!("[jockc] ERROR: Cannot read '{}': {}", cli.source, e);
            process::exit(1);
        }
    };

    // Parse
    let program = match parser::parse(&source) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[jockc] {}", e);
            process::exit(1);
        }
    };

    if cli.check {
        println!(
            "[jockc] OK: {} statement(s) parsed from '{}'",
            program.statements.len(),
            cli.source
        );
        return;
    }

    if cli.ast {
        match serde_json::to_string_pretty(&program) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("[jockc] JSON serialization error: {e}");
                process::exit(1);
            }
        }
        return;
    }

    // Default: parse + summary
    println!("[jockc] Parsed '{}' → {} statement(s)", cli.source, program.statements.len());
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
    println!("\n[jockc] Note: LLVM IR codegen not yet implemented in Rust compiler.");
    println!("[jockc] Use the Python compiler (compiler/jockc.py) for full compilation.");
}
