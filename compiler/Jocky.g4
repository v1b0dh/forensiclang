grammar Jocky;

// ─────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────
program     : statement* EOF ;

statement   : collectStmt
            | scanStmt
            | analyzeStmt
            | timelineStmt
            | correlateStmt
            | reportStmt
            | assignStmt
            | ifStmt
            | forStmt
            | funcDecl
            ;

// ─────────────────────────────────────────────────────────────────
// Core forensic statements
// ─────────────────────────────────────────────────────────────────
collectStmt : 'collect' collectTarget
              ('from' source)?
              ('using' id)?
              filterClause?
              exportClause?
            ;

collectTarget : 'memory' | 'disk' | 'registry' | 'artifacts' ;

scanStmt    : 'scan' scanTarget
              ('on' id)?
              ('filter' 'by' expr)?
            ;

scanTarget  : 'network' 'interfaces'
            | 'processes'
            | 'open' 'ports'
            | 'loaded' 'modules'
            ;

analyzeStmt : 'analyze' (id | STRING)
              'using' STRING
              ('threshold' NUMBER)?
            ;

timelineStmt : 'timeline' 'host' (STRING | id)
               'from' (TIMESTAMP | STRING) 'to' (TIMESTAMP | STRING)
               'include' '[' timelineSource (',' timelineSource)* ']'
               ('output' 'report' STRING)?
             ;

timelineSource : 'registry' | 'eventlog' | 'prefetch'
               | 'browser' | 'shellbags' | 'mft' ;

correlateStmt : 'correlate' (id | STRING)
                'with' STRING        // IOC list path
                ('flag' 'anomalies')?
              ;

reportStmt  : 'report' (id | STRING) 'as' STRING
              ('format' ('html' | 'json' | 'csv'))?
            ;

// ─────────────────────────────────────────────────────────────────
// Expressions
// ─────────────────────────────────────────────────────────────────
expr        : expr ('and'|'or') expr
            | 'not' expr
            | expr ('=='|'!='|'>'|'<'|'>='|'<=') expr
            | expr 'contains' expr
            | expr 'matches' STRING
            | primary
            ;

primary     : NUMBER | STRING | BOOL | id
            | '(' expr ')'
            ;

// ─────────────────────────────────────────────────────────────────
// Clauses
// ─────────────────────────────────────────────────────────────────
filterClause : 'filter' 'by' filterExpr (',' filterExpr)* ;
filterExpr   : id filterOp? (STRING | NUMBER | identifierList | id) ;
filterOp     : '==' | '!=' | 'contains' | 'in' ;

exportClause : 'export' 'to' 'artifact' STRING ;

source      : 'pid' (NUMBER | id)
            | 'host' (STRING | id)
            | id
            ;

// ─────────────────────────────────────────────────────────────────
// Control flow & declarations
// ─────────────────────────────────────────────────────────────────
assignStmt  : id '=' expr ;
ifStmt      : 'if' expr '{' statement* '}' ('else' '{' statement* '}')? ;
forStmt     : 'for' id 'each' id '{' statement* '}' ;
funcDecl    : 'function' id '(' paramList? ')' '{' statement* '}' ;
paramList   : id (',' id)* ;

identifierList : '[' id (',' id)* ']' ;

id          : IDENTIFIER
            | 'pid'
            | 'host'
            | 'memory'
            | 'disk'
            | 'registry'
            | 'network'
            | 'interfaces'
            | 'processes'
            | 'artifacts'
            ;

// ─────────────────────────────────────────────────────────────────
// Tokens
// ─────────────────────────────────────────────────────────────────
TIMESTAMP   : '"' [0-9][0-9][0-9][0-9] '-' [0-9][0-9] '-' [0-9][0-9] '"' ;
IDENTIFIER  : [a-zA-Z_][a-zA-Z0-9_]* ;
NUMBER      : [0-9]+ ('.' [0-9]+)? ;
STRING      : '"' (~["\r\n])* '"' ;
BOOL        : 'true' | 'false' ;
WS          : [ \t\r\n]+ -> skip ;
COMMENT     : '//' ~[\r\n]* -> skip ;
BLOCK_COMMENT : '/*' .*? '*/' -> skip ;
