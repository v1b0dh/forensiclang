//! JOCKY AST Node Definitions
//!
//! Ported from `compiler/ast/nodes.py`. Each Python `@dataclass` becomes a
//! Rust struct; the `ASTNode` base becomes a `line` field on every node.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────
// Top-level
// ─────────────────────────────────────────────────────────────────

/// Root of every JOCKY program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Statement>,
}

/// Every possible top-level statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    Collect(CollectStatement),
    Scan(ScanStatement),
    Carve(CarveStatement),
    Erase(EraseStatement),
    Analyze(AnalyzeStatement),
    Timeline(TimelineStatement),
    Correlate(CorrelateStatement),
    Report(ReportStatement),
    Assign(AssignStatement),
    Call(CallStatement),
    If(IfStatement),
    For(ForStatement),
    FuncDecl(FuncDecl),
}

// ─────────────────────────────────────────────────────────────────
// Forensic Carving & Erasure statements
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveStatement {
    pub drive: String,
    pub target_types: Vec<String>,
    pub mode: CarveMode,
    pub confidence_threshold: Option<f64>,
    pub export_name: Option<String>,
    pub scan_threats: bool,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CarveMode {
    Quick,
    Deep,
    Fragmented,
}

impl Default for CarveMode {
    fn default() -> Self {
        CarveMode::Deep
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseStatement {
    pub target_type: EraseTarget,
    pub target_path: String,
    pub method: EraseMethod,
    pub passes: Option<usize>,
    pub clean_metadata: bool,
    pub clean_slack: bool,
    pub audit_file: Option<String>,
    pub certificate_file: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EraseTarget {
    Drive,
    File,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EraseMethod {
    Zero,
    Random,
    Nist800_88Clear,
    Nist800_88Purge,
    Dod5220_22M,
    Gutmann,
}

impl Default for EraseMethod {
    fn default() -> Self {
        EraseMethod::Nist800_88Clear
    }
}

// ─────────────────────────────────────────────────────────────────
// Forensic statements
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectStatement {
    pub target: CollectTarget,
    pub source: Option<Source>,
    pub using_plugin: Option<String>,
    pub filters: Vec<FilterExpr>,
    pub export_name: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectTarget {
    Memory,
    Disk,
    Registry,
    Artifacts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatement {
    pub target: ScanTarget,
    pub interface: Option<String>,
    pub filter_expr: Option<Expr>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTarget {
    NetworkInterfaces,
    Processes,
    OpenPorts,
    LoadedModules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeStatement {
    pub target: String,
    pub plugin: String,
    pub threshold: Option<f64>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineStatement {
    pub host: String,
    pub from_time: String,
    pub to_time: String,
    pub sources: Vec<TimelineSource>,
    pub output_file: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineSource {
    Registry,
    Eventlog,
    Prefetch,
    Browser,
    Shellbags,
    Mft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateStatement {
    pub data: String,
    pub ioc_list: String,
    pub flag_anomalies: bool,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatement {
    pub target: String,
    pub filename: String,
    pub format: ReportFormat,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Html,
    Json,
    Csv,
}

impl Default for ReportFormat {
    fn default() -> Self {
        ReportFormat::Html
    }
}

// ─────────────────────────────────────────────────────────────────
// Control-flow
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignStatement {
    pub name: String,
    pub value: Expr,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStatement {
    pub callee: String,
    pub args: Vec<Expr>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfStatement {
    pub condition: Expr,
    pub then_block: Vec<Statement>,
    pub else_block: Vec<Statement>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForStatement {
    pub var: String,
    pub iterable: String,
    pub body: Vec<Statement>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncDecl {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Statement>,
    pub line: usize,
}

// ─────────────────────────────────────────────────────────────────
// Supporting structures
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub kind: SourceKind,
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    Pid,
    Host,
    Identifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterExpr {
    pub field: String,
    pub operator: FilterOp,
    pub value: FilterValue,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterOp {
    Eq,
    NotEq,
    Contains,
    In,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterValue {
    Str(String),
    Num(f64),
    IdentList(Vec<String>),
    Ident(String),
}

// ─────────────────────────────────────────────────────────────────
// Expressions
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// Binary operation: left op right
    BinOp {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
        line: usize,
    },
    /// Unary: `not expr`
    Not {
        operand: Box<Expr>,
        line: usize,
    },
    /// Literal number
    Number(f64),
    /// Literal string (without quotes)
    Str(String),
    /// Literal boolean
    Bool(bool),
    /// Identifier reference
    Ident(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    And,
    Or,
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
    Matches,
}

impl std::fmt::Display for BinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinOp::And => write!(f, "and"),
            BinOp::Or => write!(f, "or"),
            BinOp::Eq => write!(f, "=="),
            BinOp::NotEq => write!(f, "!="),
            BinOp::Gt => write!(f, ">"),
            BinOp::Lt => write!(f, "<"),
            BinOp::Gte => write!(f, ">="),
            BinOp::Lte => write!(f, "<="),
            BinOp::Contains => write!(f, "contains"),
            BinOp::Matches => write!(f, "matches"),
        }
    }
}
