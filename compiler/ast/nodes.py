"""
JOCKY AST Node Definitions
compiler/ast/nodes.py
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Any


# ─────────────────────────────────────────────────────────────────
# Base
# ─────────────────────────────────────────────────────────────────
@dataclass
class ASTNode:
    line: int = field(default=0, kw_only=True)

    def accept(self, visitor):
        method_name = f"visit_{type(self).__name__}"
        visitor_method = getattr(visitor, method_name, visitor.generic_visit)
        return visitor_method(self)


# ─────────────────────────────────────────────────────────────────
# Top-level
# ─────────────────────────────────────────────────────────────────
@dataclass
class Program(ASTNode):
    statements: List[ASTNode] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────
# Forensic statements
# ─────────────────────────────────────────────────────────────────
@dataclass
class CollectStatement(ASTNode):
    target: str                         # memory | disk | registry | artifacts
    source: "Source"
    filters: List["FilterExpr"] = field(default_factory=list)
    export_name: Optional[str] = None


@dataclass
class ScanStatement(ASTNode):
    target: str                         # processes | network_interfaces | open_ports | loaded_modules
    interface: Optional[str] = None
    filter_expr: Optional["Expression"] = None


@dataclass
class CarveStatement(ASTNode):
    drive: str
    types: List[str] = field(default_factory=list)
    mode: str = "deep"                  # quick | deep | fragmented
    confidence_threshold: Optional[float] = None
    export_name: Optional[str] = None


@dataclass
class EraseStatement(ASTNode):
    target_type: str                    # drive | file | folder
    target_path: str
    method: str                         # zero | random | nist_800_88_clear | nist_800_88_purge | dod_5220_22_m | gutmann
    passes: Optional[int] = None
    clean_metadata: bool = False
    clean_slack: bool = False
    audit_file: Optional[str] = None
    certificate_file: Optional[str] = None


@dataclass
class AnalyzeStatement(ASTNode):
    target: str                         # identifier referencing a collected artifact
    plugin: str                         # YARA / Volatility plugin name
    threshold: Optional[float] = None


@dataclass
class TimelineStatement(ASTNode):
    host: str
    from_time: str
    to_time: str
    sources: List[str]
    output_file: Optional[str] = None


@dataclass
class CorrelateStatement(ASTNode):
    data: str                           # artifact identifier
    ioc_list: str                       # path to IOC file
    flag_anomalies: bool = False


@dataclass
class ReportStatement(ASTNode):
    target: str                         # artifact identifier
    filename: str
    format: str = "html"               # html | json | csv


# ─────────────────────────────────────────────────────────────────
# Control-flow
# ─────────────────────────────────────────────────────────────────
@dataclass
class AssignStatement(ASTNode):
    name: str
    value: "Expression"


@dataclass
class CallStatement(ASTNode):
    callee: str
    args: List["Expression"] = field(default_factory=list)


@dataclass
class IfStatement(ASTNode):
    condition: "Expression"
    then_block: List[ASTNode] = field(default_factory=list)
    else_block: List[ASTNode] = field(default_factory=list)


@dataclass
class ForStatement(ASTNode):
    var: str
    iterable: str
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class FuncDecl(ASTNode):
    name: str
    params: List[str] = field(default_factory=list)
    body: List[ASTNode] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────
# Supporting structures
# ─────────────────────────────────────────────────────────────────
@dataclass
class Source(ASTNode):
    kind: str           # pid | host | identifier
    value: Any = None


@dataclass
class FilterExpr(ASTNode):
    field: str
    operator: str       # == | != | contains | in
    value: Any          # str | float | list[str]


@dataclass
class Expression(ASTNode):
    """General expression node (binary ops, unary, or leaf)."""
    operator: Optional[str] = None  # and | or | not | == | != | > | < | >= | <= | contains | matches
    left: Optional[Any] = None
    right: Optional[Any] = None
    value: Optional[Any] = None     # for literals / identifiers

    def is_literal(self) -> bool:
        return self.operator is None and self.value is not None
