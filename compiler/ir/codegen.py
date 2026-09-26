"""
JOCKY LLVM IR Code Generator
compiler/ir/codegen.py

Uses llvmlite to emit LLVM IR that calls into the forensic C runtime.
"""
from __future__ import annotations
from typing import Dict

try:
    from llvmlite import ir, binding  # pip install llvmlite
    LLVMLITE_AVAILABLE = True
except ImportError:
    LLVMLITE_AVAILABLE = False
    ir = None
    binding = None

# Import AST nodes (relative when running as package)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from compiler.ast.nodes import (
    Program, CollectStatement, ScanStatement, TimelineStatement,
    CorrelateStatement, ReportStatement, AnalyzeStatement,
    AssignStatement, IfStatement, ForStatement, FuncDecl,
)


class JockyCodeGen:
    """Walk a JOCKY AST and emit LLVM IR text."""

    def __init__(self, target: str = "windows"):
        if not LLVMLITE_AVAILABLE:
            raise ImportError("llvmlite is not installed. Run: pip install llvmlite")
        
        try:
            binding.initialize()
        except Exception:
            pass
        binding.initialize_native_target()
        binding.initialize_native_asmprinter()

        self.target = target
        self.module = ir.Module(name="jocky_module")
        self.module.triple = binding.get_default_triple()
        self.builder: ir.IRBuilder | None = None
        self.func: ir.Function | None = None
        self._string_cache: Dict[str, ir.GlobalVariable] = {}
        self._declare_runtime_functions()

    # ─────────────────────── Runtime function declarations ────────────────────
    def _declare_runtime_functions(self):
        i64 = ir.IntType(64)
        i32 = ir.IntType(32)
        i8p = ir.PointerType(ir.IntType(8))
        void = ir.VoidType()

        def extern(ret, args, name):
            fntype = ir.FunctionType(ret, args)
            fn = ir.Function(self.module, fntype, name=name)
            fn.linkage = "external"
            return fn

        self.rt = {
            # Memory
            "jocky_collect_memory":       extern(void, [i64, i8p], "jocky_collect_memory"),
            "jocky_collect_memory_linux": extern(void, [i64, i8p], "jocky_collect_memory_linux"),
            # Disk
            "jocky_collect_disk_vss":     extern(void, [i8p, i8p], "jocky_collect_disk_vss"),
            # Network
            "jocky_scan_network":         extern(void, [i8p, i8p], "jocky_scan_network"),
            # Processes
            "jocky_scan_processes":       extern(void, [i8p],       "jocky_scan_processes"),
            # Registry
            "jocky_collect_registry":     extern(void, [i8p, i8p], "jocky_collect_registry"),
            # Timeline
            "jocky_build_timeline":       extern(void, [i8p, i8p, i8p, i8p, i8p], "jocky_build_timeline"),
            # Correlate
            "jocky_correlate":            extern(void, [i8p, i8p, i32], "jocky_correlate"),
            # Report
            "jocky_generate_report":      extern(void, [i8p, i8p, i8p], "jocky_generate_report"),
            # Analyze
            "jocky_analyze":              extern(void, [i8p, i8p], "jocky_analyze"),
        }

    # ──────────────────────────── Entry point ─────────────────────────────
    def generate(self, ast: Program) -> str:
        """Walk the AST and return LLVM IR as a string."""
        main_type = ir.FunctionType(ir.IntType(32), [])
        self.func = ir.Function(self.module, main_type, name="jocky_main")
        block = self.func.append_basic_block("entry")
        self.builder = ir.IRBuilder(block)

        for stmt in ast.statements:
            self._emit_statement(stmt)

        self.builder.ret(ir.Constant(ir.IntType(32), 0))
        return str(self.module)

    # ─────────────────────────── Dispatch ─────────────────────────────────
    def _emit_statement(self, node):
        if isinstance(node, FuncDecl):
            for s in node.body:
                self._emit_statement(s)
            return
        dispatch = {
            CollectStatement:  self._emit_collect,
            ScanStatement:     self._emit_scan,
            TimelineStatement: self._emit_timeline,
            CorrelateStatement:self._emit_correlate,
            ReportStatement:   self._emit_report,
            AnalyzeStatement:  self._emit_analyze,
        }
        fn = dispatch.get(type(node))
        if fn:
            fn(node)
        # AssignStatement, IfStatement, ForStatement — future work

    # ─────────────────────────── Emitters ─────────────────────────────────
    def _emit_collect(self, node: CollectStatement):
        export = node.export_name or "output"
        if node.target == "memory":
            try:
                pid_int = int(node.source.value or 0)
            except (ValueError, TypeError):
                pid_int = 0
            pid_val = ir.Constant(ir.IntType(64), pid_int)
            name_ptr = self._str(export)
            fn_name = (
                "jocky_collect_memory_linux"
                if self.target == "linux"
                else "jocky_collect_memory"
            )
            self.builder.call(self.rt[fn_name], [pid_val, name_ptr])

        elif node.target == "disk":
            vol = self._str(str(node.source.value or "C:"))
            name_ptr = self._str(export)
            self.builder.call(self.rt["jocky_collect_disk_vss"], [vol, name_ptr])

        elif node.target == "registry":
            path = self._str(str(node.source.value or "HKLM"))
            name_ptr = self._str(export)
            self.builder.call(self.rt["jocky_collect_registry"], [path, name_ptr])

    def _emit_scan(self, node: ScanStatement):
        filter_str = ""
        if node.filter_expr and node.filter_expr.value is not None:
            filter_str = str(node.filter_expr.value)
        fp = self._str(filter_str)
        
        if "processes" in node.target:
            self.builder.call(self.rt["jocky_scan_processes"], [fp])
        elif "network" in node.target:
            iface = self._str(node.interface or "eth0")
            self.builder.call(self.rt["jocky_scan_network"], [iface, fp])

    def _emit_timeline(self, node: TimelineStatement):
        host = self._str(node.host)
        from_t = self._str(node.from_time)
        to_t = self._str(node.to_time)
        sources = self._str(",".join(node.sources))
        out = self._str(node.output_file or "timeline.html")
        self.builder.call(self.rt["jocky_build_timeline"], [host, from_t, to_t, sources, out])

    def _emit_correlate(self, node: CorrelateStatement):
        data = self._str(node.data)
        ioc = self._str(node.ioc_list)
        flag = ir.Constant(ir.IntType(32), 1 if node.flag_anomalies else 0)
        self.builder.call(self.rt["jocky_correlate"], [data, ioc, flag])

    def _emit_report(self, node: ReportStatement):
        target = self._str(node.target)
        fname = self._str(node.filename)
        fmt = self._str(node.format)
        self.builder.call(self.rt["jocky_generate_report"], [target, fname, fmt])

    def _emit_analyze(self, node: AnalyzeStatement):
        target = self._str(node.target)
        plugin = self._str(node.plugin)
        self.builder.call(self.rt["jocky_analyze"], [target, plugin])

    # ─────────────────────── String constant helper ────────────────────────
    def _str(self, s: str) -> ir.Value:
        """Return an i8* pointing to a null-terminated global string constant."""
        if s in self._string_cache:
            gv = self._string_cache[s]
        else:
            encoded = (s + "\0").encode("utf-8")
            arr_type = ir.ArrayType(ir.IntType(8), len(encoded))
            # Make the name safe for LLVM
            safe_name = f"str_{abs(hash(s)) % 0xFFFF}"
            gv = ir.GlobalVariable(self.module, arr_type, name=safe_name)
            gv.initializer = ir.Constant(arr_type, bytearray(encoded))
            gv.global_constant = True
            gv.linkage = "internal"
            self._string_cache[s] = gv

        zero = ir.Constant(ir.IntType(32), 0)
        return self.builder.gep(gv, [zero, zero], inbounds=True)


# ─────────────────── Convenience: IR-only code generator ──────────────────
class JockyIRCodeGen(JockyCodeGen):
    """Variant that doesn't require a native target — used for testing."""
    def __init__(self, target: str = "linux"):
        if not LLVMLITE_AVAILABLE:
            raise ImportError("llvmlite is not installed.")
        self.target = target
        self.module = ir.Module(name="jocky_module")
        self.module.triple = "x86_64-pc-linux-gnu"
        self.builder = None
        self.func = None
        self._string_cache = {}
        self._declare_runtime_functions()
