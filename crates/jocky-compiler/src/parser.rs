//! JOCKY Parser — pest parse tree → typed AST
//!
//! Walks the pest `Pairs` tree and produces `ast::Program`.

use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

use crate::ast::*;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct JockyParser;

/// Parse a JOCKY source string into a typed AST.
pub fn parse(source: &str) -> Result<Program, String> {
    let pairs = JockyParser::parse(Rule::program, source)
        .map_err(|e| format!("Parse error: {e}"))?;

    let mut statements = Vec::new();
    for pair in pairs {
        if pair.as_rule() == Rule::program {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::statement {
                    if let Some(stmt) = build_statement(inner)? {
                        statements.push(stmt);
                    }
                }
            }
        }
    }

    Ok(Program { statements })
}

// ─────────────────────────── Statement dispatch ──────────────────

fn build_statement(pair: Pair<Rule>) -> Result<Option<Statement>, String> {
    let inner = first_inner(pair)?;
    let line = inner.line_col().0;

    match inner.as_rule() {
        Rule::collect_stmt => Ok(Some(Statement::Collect(build_collect(inner, line)?))),
        Rule::scan_stmt => Ok(Some(Statement::Scan(build_scan(inner, line)?))),
        Rule::analyze_stmt => Ok(Some(Statement::Analyze(build_analyze(inner, line)?))),
        Rule::timeline_stmt => Ok(Some(Statement::Timeline(build_timeline(inner, line)?))),
        Rule::correlate_stmt => Ok(Some(Statement::Correlate(build_correlate(inner, line)?))),
        Rule::report_stmt => Ok(Some(Statement::Report(build_report(inner, line)?))),
        Rule::assign_stmt => Ok(Some(Statement::Assign(build_assign(inner, line)?))),
        Rule::if_stmt => Ok(Some(Statement::If(build_if(inner, line)?))),
        Rule::for_stmt => Ok(Some(Statement::For(build_for(inner, line)?))),
        Rule::func_decl => Ok(Some(Statement::FuncDecl(build_func_decl(inner, line)?))),
        Rule::EOI => Ok(None),
        other => Err(format!("Unexpected rule in statement: {other:?}")),
    }
}

// ─────────────────────────── Collect ─────────────────────────────

fn build_collect(pair: Pair<Rule>, line: usize) -> Result<CollectStatement, String> {
    let mut target = CollectTarget::Memory;
    let mut source = None;
    let mut using_plugin = None;
    let mut filters = Vec::new();
    let mut export_name = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::collect_target => {
                target = match inner.as_str() {
                    "memory" => CollectTarget::Memory,
                    "disk" => CollectTarget::Disk,
                    "registry" => CollectTarget::Registry,
                    "artifacts" => CollectTarget::Artifacts,
                    other => return Err(format!("Unknown collect target: {other}")),
                };
            }
            Rule::source => source = Some(build_source(inner)?),
            Rule::ident => using_plugin = Some(inner.as_str().to_string()),
            Rule::filter_clause => filters = build_filter_clause(inner)?,
            Rule::export_clause => {
                export_name = inner
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::string)
                    .map(|p| strip_quotes(p.as_str()));
            }
            _ => {}
        }
    }

    Ok(CollectStatement {
        target,
        source,
        using_plugin,
        filters,
        export_name,
        line,
    })
}

// ─────────────────────────── Scan ────────────────────────────────

fn build_scan(pair: Pair<Rule>, line: usize) -> Result<ScanStatement, String> {
    let mut target = ScanTarget::Processes;
    let mut interface = None;
    let mut filter_expr = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::scan_target => {
                target = match inner.as_str().trim() {
                    s if s.contains("network") => ScanTarget::NetworkInterfaces,
                    s if s.contains("processes") => ScanTarget::Processes,
                    s if s.contains("open") => ScanTarget::OpenPorts,
                    s if s.contains("loaded") => ScanTarget::LoadedModules,
                    other => return Err(format!("Unknown scan target: {other}")),
                };
            }
            Rule::ident => interface = Some(inner.as_str().to_string()),
            Rule::expr => filter_expr = Some(build_expr(inner)?),
            _ => {}
        }
    }

    Ok(ScanStatement {
        target,
        interface,
        filter_expr,
        line,
    })
}

// ─────────────────────────── Analyze ─────────────────────────────

fn build_analyze(pair: Pair<Rule>, line: usize) -> Result<AnalyzeStatement, String> {
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut target = String::new();
    let mut plugin = String::new();
    let mut threshold = None;

    for child in &children {
        match child.as_rule() {
            Rule::ident => {
                if target.is_empty() {
                    target = child.as_str().to_string();
                }
            }
            Rule::string => {
                let s = strip_quotes(child.as_str());
                if target.is_empty() {
                    target = s;
                } else if plugin.is_empty() {
                    plugin = s;
                }
            }
            Rule::number => {
                threshold = child.as_str().parse::<f64>().ok();
            }
            _ => {}
        }
    }

    Ok(AnalyzeStatement {
        target,
        plugin,
        threshold,
        line,
    })
}

// ─────────────────────────── Timeline ────────────────────────────

fn build_timeline(pair: Pair<Rule>, line: usize) -> Result<TimelineStatement, String> {
    let mut host = String::new();
    let mut from_time = String::new();
    let mut to_time = String::new();
    let mut sources = Vec::new();
    let mut output_file = None;
    let mut time_count = 0;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident | Rule::string if host.is_empty() => {
                host = strip_quotes(inner.as_str());
            }
            Rule::timestamp | Rule::string if time_count == 0 && !host.is_empty() => {
                from_time = strip_quotes(inner.as_str());
                time_count += 1;
            }
            Rule::timestamp | Rule::string if time_count == 1 => {
                to_time = strip_quotes(inner.as_str());
                time_count += 1;
            }
            Rule::timeline_source => {
                sources.push(match inner.as_str().trim() {
                    "registry" => TimelineSource::Registry,
                    "eventlog" => TimelineSource::Eventlog,
                    "prefetch" => TimelineSource::Prefetch,
                    "browser" => TimelineSource::Browser,
                    "shellbags" => TimelineSource::Shellbags,
                    "mft" => TimelineSource::Mft,
                    other => return Err(format!("Unknown timeline source: {other}")),
                });
            }
            Rule::string if time_count >= 2 => {
                output_file = Some(strip_quotes(inner.as_str()));
            }
            _ => {}
        }
    }

    Ok(TimelineStatement {
        host,
        from_time,
        to_time,
        sources,
        output_file,
        line,
    })
}

// ─────────────────────────── Correlate ───────────────────────────

fn build_correlate(pair: Pair<Rule>, line: usize) -> Result<CorrelateStatement, String> {
    let text = pair.as_str().to_string();
    let mut data = String::new();
    let mut ioc_list = String::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident | Rule::string if data.is_empty() => {
                data = strip_quotes(inner.as_str());
            }
            Rule::string if ioc_list.is_empty() => {
                ioc_list = strip_quotes(inner.as_str());
            }
            _ => {}
        }
    }

    let flag_anomalies = text.contains("flag") && text.contains("anomalies");

    Ok(CorrelateStatement {
        data,
        ioc_list,
        flag_anomalies,
        line,
    })
}

// ─────────────────────────── Report ──────────────────────────────

fn build_report(pair: Pair<Rule>, line: usize) -> Result<ReportStatement, String> {
    let mut target = String::new();
    let mut filename = String::new();
    let mut format = ReportFormat::Html;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident | Rule::string if target.is_empty() => {
                target = strip_quotes(inner.as_str());
            }
            Rule::string if filename.is_empty() => {
                filename = strip_quotes(inner.as_str());
            }
            Rule::format_clause => {
                if let Some(ft) = inner.into_inner().find(|p| p.as_rule() == Rule::format_type) {
                    format = match ft.as_str() {
                        "html" => ReportFormat::Html,
                        "json" => ReportFormat::Json,
                        "csv" => ReportFormat::Csv,
                        _ => ReportFormat::Html,
                    };
                }
            }
            _ => {}
        }
    }

    Ok(ReportStatement {
        target,
        filename,
        format,
        line,
    })
}

// ─────────────────────────── Assign ──────────────────────────────

fn build_assign(pair: Pair<Rule>, line: usize) -> Result<AssignStatement, String> {
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or("Missing var name")?.as_str().to_string();
    let value_pair = inner.next().ok_or("Missing assignment value")?;
    let value = build_expr(value_pair)?;

    Ok(AssignStatement { name, value, line })
}

// ─────────────────────────── If/Else ─────────────────────────────

fn build_if(pair: Pair<Rule>, line: usize) -> Result<IfStatement, String> {
    let mut parts = pair.into_inner();
    let condition = build_expr(parts.next().ok_or("Missing if condition")?)?;

    let then_pair = parts.next().ok_or("Missing then block")?;
    let then_block = build_block(then_pair)?;

    let else_block = if let Some(else_pair) = parts.next() {
        build_block(else_pair)?
    } else {
        Vec::new()
    };

    Ok(IfStatement {
        condition,
        then_block,
        else_block,
        line,
    })
}

// ─────────────────────────── For ─────────────────────────────────

fn build_for(pair: Pair<Rule>, line: usize) -> Result<ForStatement, String> {
    let mut parts = pair.into_inner();
    let var = parts.next().ok_or("Missing loop var")?.as_str().to_string();
    let iterable = parts.next().ok_or("Missing iterable")?.as_str().to_string();
    let body_pair = parts.next().ok_or("Missing for body")?;
    let body = build_block(body_pair)?;

    Ok(ForStatement {
        var,
        iterable,
        body,
        line,
    })
}

// ─────────────────────────── FuncDecl ────────────────────────────

fn build_func_decl(pair: Pair<Rule>, line: usize) -> Result<FuncDecl, String> {
    let mut name = String::new();
    let mut params = Vec::new();
    let mut body = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident if name.is_empty() => name = inner.as_str().to_string(),
            Rule::param_list => {
                for p in inner.into_inner() {
                    if p.as_rule() == Rule::ident {
                        params.push(p.as_str().to_string());
                    }
                }
            }
            Rule::block => body = build_block(inner)?,
            _ => {}
        }
    }

    Ok(FuncDecl {
        name,
        params,
        body,
        line,
    })
}

// ─────────────────────────── Block ───────────────────────────────

fn build_block(pair: Pair<Rule>) -> Result<Vec<Statement>, String> {
    let mut stmts = Vec::new();
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::statement {
            if let Some(stmt) = build_statement(inner)? {
                stmts.push(stmt);
            }
        }
    }
    Ok(stmts)
}

// ─────────────────────────── Source ──────────────────────────────

fn build_source(pair: Pair<Rule>) -> Result<Source, String> {
    let line = pair.line_col().0;
    let text = pair.as_str().to_string();

    let mut kind = SourceKind::Identifier;
    let mut value = String::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::number => {
                kind = SourceKind::Pid;
                value = inner.as_str().to_string();
            }
            Rule::string => {
                kind = SourceKind::Host;
                value = strip_quotes(inner.as_str());
            }
            Rule::ident => {
                if text.starts_with("pid") {
                    kind = SourceKind::Pid;
                } else if text.starts_with("host") {
                    kind = SourceKind::Host;
                } else {
                    kind = SourceKind::Identifier;
                }
                value = inner.as_str().to_string();
            }
            _ => {}
        }
    }

    Ok(Source { kind, value, line })
}

// ─────────────────────────── Filter ──────────────────────────────

fn build_filter_clause(pair: Pair<Rule>) -> Result<Vec<FilterExpr>, String> {
    let mut filters = Vec::new();
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::filter_expr {
            filters.push(build_filter_expr(inner)?);
        }
    }
    Ok(filters)
}

fn build_filter_expr(pair: Pair<Rule>) -> Result<FilterExpr, String> {
    let line = pair.line_col().0;
    let mut field = String::new();
    let mut operator = FilterOp::In;
    let mut value = FilterValue::Str(String::new());

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident if field.is_empty() => field = inner.as_str().to_string(),
            Rule::filter_op => {
                operator = match inner.as_str().trim() {
                    "==" => FilterOp::Eq,
                    "!=" => FilterOp::NotEq,
                    "contains" => FilterOp::Contains,
                    "in" => FilterOp::In,
                    _ => FilterOp::In,
                };
            }
            Rule::filter_value => {
                value = build_filter_value(inner)?;
            }
            _ => {}
        }
    }

    Ok(FilterExpr {
        field,
        operator,
        value,
        line,
    })
}

fn build_filter_value(pair: Pair<Rule>) -> Result<FilterValue, String> {
    let inner = first_inner(pair)?;
    match inner.as_rule() {
        Rule::string => Ok(FilterValue::Str(strip_quotes(inner.as_str()))),
        Rule::number => Ok(FilterValue::Num(
            inner.as_str().parse().unwrap_or(0.0),
        )),
        Rule::identifier_list => {
            let items: Vec<String> = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::ident)
                .map(|p| p.as_str().to_string())
                .collect();
            Ok(FilterValue::IdentList(items))
        }
        Rule::ident => Ok(FilterValue::Ident(inner.as_str().to_string())),
        other => Err(format!("Unexpected filter value rule: {other:?}")),
    }
}

// ─────────────────────────── Expressions ─────────────────────────

fn build_expr(pair: Pair<Rule>) -> Result<Expr, String> {
    let line = pair.line_col().0;

    match pair.as_rule() {
        Rule::expr => {
            let mut parts: Vec<Pair<Rule>> = pair.into_inner().collect();

            if parts.len() == 1 {
                return build_expr(parts.remove(0));
            }

            // Precedence climbing: left-assoc binary ops
            let mut result = build_expr(parts.remove(0))?;
            while parts.len() >= 2 {
                let op_pair = parts.remove(0);
                let right_pair = parts.remove(0);
                let op = parse_bin_op(op_pair.as_str())?;
                let right = build_expr(right_pair)?;
                result = Expr::BinOp {
                    op,
                    left: Box::new(result),
                    right: Box::new(right),
                    line,
                };
            }
            Ok(result)
        }
        Rule::unary => {
            let mut parts: Vec<Pair<Rule>> = pair.into_inner().collect();
            if parts.len() == 2 && parts[0].as_rule() == Rule::not_op {
                parts.remove(0); // consume 'not'
                let operand = build_expr(parts.remove(0))?;
                Ok(Expr::Not {
                    operand: Box::new(operand),
                    line,
                })
            } else if parts.len() == 1 {
                build_expr(parts.remove(0))
            } else {
                Err(format!("Unexpected unary expression structure"))
            }
        }
        Rule::primary => {
            let inner = first_inner(pair)?;
            match inner.as_rule() {
                Rule::number => Ok(Expr::Number(inner.as_str().parse().unwrap_or(0.0))),
                Rule::string => Ok(Expr::Str(strip_quotes(inner.as_str()))),
                Rule::boolean => Ok(Expr::Bool(inner.as_str() == "true")),
                Rule::ident => Ok(Expr::Ident(inner.as_str().to_string())),
                Rule::expr => build_expr(inner),
                other => Err(format!("Unexpected primary rule: {other:?}")),
            }
        }
        // If we get a leaf token directly
        Rule::number => Ok(Expr::Number(pair.as_str().parse().unwrap_or(0.0))),
        Rule::string => Ok(Expr::Str(strip_quotes(pair.as_str()))),
        Rule::boolean => Ok(Expr::Bool(pair.as_str() == "true")),
        Rule::ident => Ok(Expr::Ident(pair.as_str().to_string())),
        other => Err(format!("Cannot build expr from rule: {other:?}")),
    }
}

fn parse_bin_op(s: &str) -> Result<BinOp, String> {
    match s.trim() {
        "and" => Ok(BinOp::And),
        "or" => Ok(BinOp::Or),
        "==" => Ok(BinOp::Eq),
        "!=" => Ok(BinOp::NotEq),
        ">" => Ok(BinOp::Gt),
        "<" => Ok(BinOp::Lt),
        ">=" => Ok(BinOp::Gte),
        "<=" => Ok(BinOp::Lte),
        "contains" => Ok(BinOp::Contains),
        "matches" => Ok(BinOp::Matches),
        other => Err(format!("Unknown binary operator: {other}")),
    }
}

// ──────────────────────────── Helpers ────────────────────────────

fn first_inner(pair: Pair<Rule>) -> Result<Pair<Rule>, String> {
    pair.into_inner()
        .next()
        .ok_or_else(|| "Expected inner pair".to_string())
}

fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

// ─────────────────────────── Tests ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_collect_memory() {
        let src = r#"collect memory from pid 1234 export to artifact "test""#;
        let program = parse(src).unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::Collect(c) => {
                assert_eq!(c.target, CollectTarget::Memory);
                assert_eq!(c.export_name.as_deref(), Some("test"));
            }
            other => panic!("Expected Collect, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_scan_processes() {
        let src = r#"scan processes"#;
        let program = parse(src).unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::Scan(s) => assert_eq!(s.target, ScanTarget::Processes),
            other => panic!("Expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_timeline() {
        let src = r#"
            timeline host "DESKTOP-XYZ"
              from "2026-01-01" to "2026-09-25"
              include [registry, eventlog, prefetch]
              output report "timeline.html"
        "#;
        let program = parse(src).unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::Timeline(t) => {
                assert_eq!(t.host, "DESKTOP-XYZ");
                assert_eq!(t.from_time, "2026-01-01");
                assert_eq!(t.to_time, "2026-09-25");
                assert_eq!(t.sources.len(), 3);
                assert_eq!(t.output_file.as_deref(), Some("timeline.html"));
            }
            other => panic!("Expected Timeline, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_correlate_with_flag() {
        let src = r#"correlate "suspicious_heap" with "known_malware.ioc" flag anomalies"#;
        let program = parse(src).unwrap();
        match &program.statements[0] {
            Statement::Correlate(c) => {
                assert_eq!(c.data, "suspicious_heap");
                assert_eq!(c.ioc_list, "known_malware.ioc");
                assert!(c.flag_anomalies);
            }
            other => panic!("Expected Correlate, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_report_json() {
        let src = r#"report "output" as "report.json" format json"#;
        let program = parse(src).unwrap();
        match &program.statements[0] {
            Statement::Report(r) => {
                assert_eq!(r.target, "output");
                assert_eq!(r.filename, "report.json");
                assert_eq!(r.format, ReportFormat::Json);
            }
            other => panic!("Expected Report, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_demo_script() {
        let src = r#"
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
        "#;
        let program = parse(src).unwrap();
        assert_eq!(program.statements.len(), 5);
    }
}
