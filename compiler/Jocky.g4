grammar Jocky;

// ─────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────
program     : statement* EOF ;

statement   : collectStmt
            | scanStmt
            | carveStmt
            | eraseStmt
            | analyzeStmt
            | timelineStmt
            | correlateStmt
            | reportStmt
            | assignStmt
            | callStmt
            | ifStmt
            | forStmt
            | funcDecl
            ;

// ─────────────────────────────────────────────────────────────────
// Core forensic statements
// ─────────────────────────────────────────────────────────────────
collectStmt : 'collect' collectTarget
              ('from' source)?
              ('using' usingPlugin=id)?
              filterClause?
              exportClause?
            ;

collectTarget : 'memory' | 'disk' | 'registry' | 'artifacts' ;

scanStmt    : 'scan' scanTarget
              ('on' ifaceName=id)?
              ('filter' 'by' filterBody=expr)?
            ;

scanTarget  : 'network' 'interfaces'
            | 'processes'
            | 'open' 'ports'
            | 'loaded' 'modules'
            ;

carveStmt   : 'carve' 'disk' 'from' 'drive' drive=strOrId
              ('types' '[' (carveType (',' carveType)*)? ']')?
              ('mode' carveMode)?
              ('confidence_threshold' threshold=NUMBER)?
              exportClause?
            ;

carveType   : 'pdf' | 'png' | 'jpg' | 'jpeg' | 'gif'
            | 'zip' | 'docx' | 'xlsx' | 'pptx' | 'office'
            | 'sqlite' | 'pcap' | 'pe' | 'exe' | 'dll' | 'elf'
            | 'all' | id
            ;

carveMode   : 'quick' | 'deep' | 'fragmented' ;

eraseStmt   : 'erase' targetType=eraseTarget targetPath=strOrId
              'method' method=eraseMethod
              ('passes' passes=NUMBER)?
              ('clean_metadata' cleanMetadata=boolean)?
              ('clean_slack' cleanSlack=boolean)?
              ('audit' auditFile=strOrId)?
              ('certificate' certFile=strOrId)?
            ;

boolean     : BOOL | 'true' | 'false' ;


eraseTarget : 'drive' | 'file' | 'folder' ;

eraseMethod : 'zero' | 'random' | 'nist_800_88_clear' | 'nist_800_88_purge' | 'dod_5220_22_m' | 'gutmann' | id ;

strOrId     : id | STRING ;

analyzeStmt : 'analyze' targetRef=analyzeTarget
              'using' pluginName=STRING
              ('threshold' thresholdVal=NUMBER)?
            ;

analyzeTarget : id | STRING ;

timelineStmt : 'timeline' 'host' hostName=timelineHost
               'from' fromTime=timelineTime 'to' toTime=timelineTime
               'include' '[' timelineSource (',' timelineSource)* ']'
               ('output' 'report' outputFile=STRING)?
             ;

timelineHost  : id | STRING ;
timelineTime  : TIMESTAMP | STRING ;

timelineSource : 'registry' | 'eventlog' | 'prefetch'
               | 'browser' | 'shellbags' | 'mft' ;

correlateStmt : 'correlate' dataRef=correlateTarget
                'with' iocPath=STRING
                ('flag' 'anomalies')?
              ;

correlateTarget : id | STRING ;

reportStmt  : 'report' targetRef=reportTarget 'as' outputName=STRING
              formatClause?
            ;

reportTarget : id | STRING ;

formatClause : 'format' formatType=('html' | 'json' | 'csv') ;

// ─────────────────────────────────────────────────────────────────
// Expressions
// ─────────────────────────────────────────────────────────────────
expr        : expr op=('and'|'or') expr
            | 'not' expr
            | expr op=('=='|'!='|'>'|'<'|'>='|'<=') expr
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
filterExpr   : fieldName=id filterOp? filterValue ;
filterValue  : STRING | NUMBER | identifierList | id ;
filterOp     : '==' | '!=' | 'contains' | 'in' ;

exportClause : 'export' ('to' 'artifact')? exportName=strOrId ;

source      : 'pid' pidValue=pidRef
            | 'host' hostValue=hostRef
            | idValue=id
            ;

pidRef      : NUMBER | id ;
hostRef     : STRING | id ;

// ─────────────────────────────────────────────────────────────────
// Control flow & declarations
// ─────────────────────────────────────────────────────────────────
assignStmt  : varName=id '=' assignValue=expr ;

callStmt    : funcName=id '(' (expr (',' expr)*)? ')' ;

ifStmt      : 'if' condition=expr thenBlock=block
              ('else' elseBlock=block)?
            ;

block       : '{' statement* '}' ;

forStmt     : 'for' loopVar=id 'each' iterName=id forBody=block ;

funcDecl    : 'function' funcName=id '(' paramList? ')' funcBody=block ;
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
            | 'drive'
            | 'file'
            | 'folder'
            | 'method'
            | 'passes'
            | 'clean_metadata'
            | 'clean_slack'
            | 'audit'
            | 'certificate'
            | 'types'
            | 'mode'
            | 'confidence_threshold'
            ;

// ─────────────────────────────────────────────────────────────────
// Tokens
// ─────────────────────────────────────────────────────────────────
TIMESTAMP   : '"' [0-9][0-9][0-9][0-9] '-' [0-9][0-9] '-' [0-9][0-9] '"' ;
BOOL        : 'true' | 'false' ;
IDENTIFIER  : [a-zA-Z_][a-zA-Z0-9_]* ;
NUMBER      : [0-9]+ ('.' [0-9]+)? ;
STRING      : '"' (~["\r\n])* '"' ;
WS          : [ \t\r\n]+ -> skip ;
COMMENT     : '//' ~[\r\n]* -> skip ;
BLOCK_COMMENT : '/*' .*? '*/' -> skip ;
