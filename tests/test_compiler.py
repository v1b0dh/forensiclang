"""
JOCKY Compiler Test Suite
tests/test_compiler.py
"""
import sys
import os
import pytest

# Allow import from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Conditionally import compiler ─────────────────────────────────
try:
    from compiler.jockc import compile_string
    COMPILER_AVAILABLE = True
except ImportError:
    COMPILER_AVAILABLE = False

skip_if_no_compiler = pytest.mark.skipif(
    not COMPILER_AVAILABLE,
    reason="ANTLR4 generated sources not available (run antlr4 first)"
)

# ── Tests ─────────────────────────────────────────────────────────
@skip_if_no_compiler
def test_collect_memory():
    script = 'collect memory from pid 1234 export to artifact "test"'
    ir = compile_string(script)
    assert 'jocky_collect_memory' in ir
    assert 'call void' in ir


@skip_if_no_compiler
def test_collect_disk():
    script = 'collect disk from host "192.168.1.1" export to artifact "disk_img"'
    ir = compile_string(script)
    assert 'jocky_collect_disk_vss' in ir


@skip_if_no_compiler
def test_scan_processes():
    ir = compile_string('scan processes filter by name contains "powershell"')
    assert 'jocky_scan_processes' in ir


@skip_if_no_compiler
def test_scan_network():
    ir = compile_string('scan network interfaces on eth0')
    assert 'jocky_scan_network' in ir


@skip_if_no_compiler
def test_timeline_statement():
    script = '''
timeline host "DESKTOP-XYZ"
  from "2026-01-01" to "2026-09-25"
  include [registry, eventlog, prefetch]
  output report "timeline.html"
'''
    ir = compile_string(script)
    assert 'jocky_build_timeline' in ir


@skip_if_no_compiler
def test_correlate():
    script = '''
collect memory from pid 999 export to artifact "mem"
correlate "mem" with "iocs.json" flag anomalies
'''
    ir = compile_string(script)
    assert 'jocky_correlate' in ir


@skip_if_no_compiler
def test_report_html():
    ir = compile_string('report "output" as "report.html" format html')
    assert 'jocky_generate_report' in ir


@skip_if_no_compiler
def test_report_json():
    ir = compile_string('report "output" as "report.json" format json')
    assert 'jocky_generate_report' in ir


@skip_if_no_compiler
def test_cross_platform_ir_structure():
    """Same script should produce equivalent IR call count on both platforms."""
    script = 'scan processes filter by name contains "cmd"'
    ir_linux   = compile_string(script, target='linux')
    ir_windows = compile_string(script, target='windows')
    assert ir_linux.count('call void') == ir_windows.count('call void')


@skip_if_no_compiler
def test_demo_script():
    """Full SIH demo script should compile without errors."""
    script = '''
scan processes
  filter by parent_pid == 1

collect memory from pid 4512
  filter by region [heap]
  export to artifact "suspicious_heap"

timeline host "DEMO-HOST"
  from "2026-09-20" to "2026-09-25"
  include [registry, eventlog, prefetch, shellbags]
  output report "persistence_analysis.html"

correlate "suspicious_heap" with "known_malware.ioc"
  flag anomalies

report "persistence_analysis" as "final_report"
  format html
'''
    ir = compile_string(script)
    assert ir is not None
    assert 'jocky_main' in ir


# ── AST node tests (no ANTLR needed) ─────────────────────────────
def test_ast_program_instantiation():
    from compiler.ast.nodes import Program, CollectStatement, Source
    prog = Program(statements=[
        CollectStatement(target='memory', source=Source(kind='pid', value=1234), line=1)
    ])
    assert len(prog.statements) == 1
    assert prog.statements[0].target == 'memory'


def test_ast_expression():
    from compiler.ast.nodes import Expression
    e = Expression(operator='==', left=Expression(value='name'), right=Expression(value='cmd.exe'))
    assert e.operator == '=='
    assert e.left.value == 'name'


def test_ast_timeline():
    from compiler.ast.nodes import TimelineStatement
    ts = TimelineStatement(
        host='DEMO', from_time='2026-01-01', to_time='2026-12-31',
        sources=['registry', 'eventlog'], output_file='out.html'
    )
    assert 'registry' in ts.sources
    assert ts.output_file == 'out.html'
