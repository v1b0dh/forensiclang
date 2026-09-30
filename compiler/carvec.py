#!/usr/bin/env python3
"""
CARVE Compiler Driver — carvec
Usage: carvec <source.crv> [output] [--ir-only] [--target {windows,linux}]

compiler/carvec.py
"""
from __future__ import annotations
import sys
import os
import subprocess
import tempfile
import argparse

# Resolve package root and prevent shadowing standard library 'ast'
ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ROOT)
if ROOT in sys.path:
    sys.path.remove(ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from antlr4 import CommonTokenStream, FileStream, InputStream

try:
    from compiler.generated.JockyLexer import JockyLexer
    from compiler.generated.JockyParser import JockyParser
    GENERATED = True
except ImportError:
    GENERATED = False

from compiler.ast.builder import ASTBuilder
from compiler.ir.codegen import JockyCodeGen


# ──────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────

def compile_string(source_code: str, target: str = "windows") -> str:
    """
    Compile a CARVE source string and return LLVM IR as a string.
    Used by tests, server runners, and the REPL.
    """
    if not GENERATED:
        raise RuntimeError(
            "ANTLR4 generated sources not found. "
            "Run: cd compiler && antlr4 -Dlanguage=Python3 -visitor -o generated/ Jocky.g4"
        )

    input_stream = InputStream(source_code)
    lexer = JockyLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = JockyParser(stream)
    tree = parser.program()

    builder = ASTBuilder()
    ast = builder.visit(tree)

    codegen = JockyCodeGen(target=target)
    return codegen.generate(ast)


def compile_file(source_path: str, output_path: str, target: str = "windows") -> None:
    """
    Full compilation pipeline:
      source .crv/.jky → lex/parse → AST → LLVM IR → native binary (via clang-17)
    """
    if not GENERATED:
        raise RuntimeError("Run antlr4 to generate parser sources first.")

    print(f"[carvec] Compiling {source_path} ...")

    # 1. Lex + Parse
    input_stream = FileStream(source_path, encoding="utf-8")
    lexer = JockyLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = JockyParser(stream)
    tree = parser.program()

    if parser.getNumberOfSyntaxErrors() > 0:
        print(f"[carvec] ERROR: {parser.getNumberOfSyntaxErrors()} syntax error(s). Aborting.")
        sys.exit(1)

    # 2. Build AST
    builder = ASTBuilder()
    ast = builder.visit(tree)

    # 3. Generate LLVM IR
    codegen = JockyCodeGen(target=target)
    llvm_ir = codegen.generate(ast)

    # 4. Write .ll to a temp file
    ir_path = output_path + ".ll"
    with open(ir_path, "w", encoding="utf-8") as f:
        f.write(llvm_ir)

    print(f"[carvec] IR written to {ir_path}")

    # 5. Compile IR → native binary via clang
    runtime_dir = os.path.join(os.path.dirname(ROOT), "runtime", "build")
    clang_cmd = [
        "clang-17",
        ir_path,
        f"-L{runtime_dir}",
        "-lcarve_runtime",
        "-o", output_path,
        "-O2",
    ]
    print(f"[carvec] Invoking clang: {' '.join(clang_cmd)}")
    subprocess.run(clang_cmd, check=True)

    print(f"[carvec] [OK] Compiled -> {output_path}")


# ──────────────────────────────────────────────────────────────────
# CLI entrypoint
# ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="carvec",
        description="CARVE forensic-script compiler",
    )
    parser.add_argument("source", help="Path to .crv or .jky source file")
    parser.add_argument("output", nargs="?", default=None, help="Output binary path (default: source basename)")
    parser.add_argument("--target", choices=["windows", "linux"], default="windows",
                        help="Target OS (default: windows)")
    parser.add_argument("--ir-only", action="store_true",
                        help="Only emit LLVM IR, do not invoke clang")
    args = parser.parse_args()

    out = args.output or os.path.splitext(args.source)[0]

    if args.ir_only:
        with open(args.source, encoding="utf-8") as f:
            src = f.read()
        ir_text = compile_string(src, target=args.target)
        ir_out = out + ".ll"
        with open(ir_out, "w", encoding="utf-8") as f:
            f.write(ir_text)
        print(f"[carvec] IR only -> {ir_out}")
    else:
        compile_file(args.source, out, target=args.target)


if __name__ == "__main__":
    main()
