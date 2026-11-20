"""The on-premise safety net: what this gateway will and will not run.

**This module assumes Qlar is hostile.** Qlar already validates the SQL it generates, but
the whole point of running a gateway inside the customer's network is that the customer
should not have to take Qlar's word for it. If Qlar's cloud were compromised tomorrow, the
blast radius should still be "read the tables the customer approved", not "run arbitrary
SQL as the database user".

Three independent layers, in increasing order of strength:

1. **Parse** the statement with `sqlglot` and require exactly one `SELECT`/`WITH`. A parser
   sees through comments, string literals and whitespace tricks that defeat pattern
   matching. Anything that fails to parse is refused rather than guessed at.
2. **Refuse known escape hatches** per dialect — the functions and clauses that turn a
   read into a file read, a shell command or a network call.
3. **Optional table allowlist** from the customer's own config file.

A fourth layer lives outside this module and is the strongest of all: `executor.py` runs
every statement in a `READ ONLY` transaction, and the documentation tells operators to
point the gateway at a read-only database account. Those are enforced by the database
itself, not by us.
"""

from __future__ import annotations

import re

import sqlglot
from sqlglot import exp

# sqlglot's dialect name for each provider we support.
DIALECTS = {
    "postgresql": "postgres",
    "mysql": "mysql",
    "sqlserver": "tsql",
    "oracle": "oracle",
    "parquet": "duckdb",
}

# Schemas that an `introspect` job is allowed to read. A schema-discovery job is still a
# normal SELECT, but it is the one case where the table allowlist cannot apply, so it is
# confined to catalog objects instead.
CATALOG_SCHEMAS = {
    "postgresql": {"information_schema", "pg_catalog"},
    "mysql": {"information_schema", "performance_schema", "mysql"},
    "sqlserver": {"information_schema", "sys"},
    "oracle": {"sys", "public"},
    "parquet": {"information_schema"},
}

# Providers where every table reference must be a plain name. DuckDB treats anything in a
# FROM clause that is not a known table as a way to read files - `read_parquet(...)`,
# `read_csv(...)`, `glob(...)`, `query('...')`, or simply `FROM 'file.parquet'` - so there a
# table function or a quoted path is refused outright, not judged by name.
PLAIN_TABLES_ONLY = {"parquet"}

# Oracle exposes its catalog as unqualified USER_*/ALL_*/DBA_* views rather than a schema,
# so catalog detection there is by name prefix.
ORACLE_CATALOG_PREFIXES = ("user_", "all_", "dba_", "v$", "gv$")

# Statement node types that are never acceptable, whatever the dialect. `exp.Command` is
# sqlglot's catch-all for statements it does not model (GRANT, COPY, CALL, SET, ...) —
# refusing it is what keeps an unknown statement type from slipping through unexamined.
FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.Merge,
    exp.Command,
    exp.Grant,
    exp.Use,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Set,
    exp.Into,  # SELECT ... INTO OUTFILE / INTO new_table
) + tuple(
    # DuckDB statements that write files, attach databases or load code. Looked up by name
    # because older sqlglot releases do not model all of them; when a class is missing the
    # statement still fails the SELECT-only root check below.
    node
    for node in (
        getattr(exp, name, None)
        for name in ("Copy", "Pragma", "Attach", "Detach", "Install", "Export", "Lock")
    )
    if isinstance(node, type)
)

# DuckDB functions that read files, list folders, run SQL from a string or read the
# environment. Checked only for DuckDB-backed providers and only as function calls: names
# like `query` or `glob` are far too common as column names to match as text.
DUCKDB_FORBIDDEN_FUNCTIONS = {
    "read_parquet",
    "parquet_scan",
    "parquet_metadata",
    "parquet_file_metadata",
    "parquet_kv_metadata",
    "parquet_schema",
    "read_csv",
    "read_csv_auto",
    "sniff_csv",
    "read_json",
    "read_json_auto",
    "read_json_objects",
    "read_ndjson",
    "read_ndjson_auto",
    "read_ndjson_objects",
    "read_text",
    "read_blob",
    "read_xlsx",
    "glob",
    "query",
    "query_table",
    "getenv",
    "iceberg_scan",
    "delta_scan",
    "sqlite_scan",
    "postgres_scan",
    "mysql_scan",
    "current_setting",
    "duckdb_settings",
    "duckdb_extensions",
    "duckdb_secrets",
    "which_secret",
}

# Functions and constructs that read files, write files, run programs or open sockets.
# Matched on the function name a parser extracted, not on raw text, so `pg_read_file`
# hidden behind whitespace or comments is still caught.
FORBIDDEN_FUNCTIONS = {
    # PostgreSQL
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
    "dblink",
    "dblink_connect",
    "dblink_exec",
    "pg_sleep",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "query_to_xml",
    "pg_read_server_files",
    # MySQL
    "load_file",
    "sleep",
    "benchmark",
    # SQL Server
    "openrowset",
    "openquery",
    "opendatasource",
    "xp_cmdshell",
    "xp_dirtree",
    "xp_fileexist",
    "xp_regread",
    "sp_oacreate",
    "sp_oamethod",
    "sp_executesql",
    # Oracle
    "utl_file",
    "utl_http",
    "utl_smtp",
    "utl_tcp",
    "utl_inaddr",
    "dbms_lob",
    "dbms_scheduler",
    "dbms_java",
    "dbms_lock",
    "httpuritype",
    "dbms_xmlgen",
    # Added in 0.4.1 to match Qlar's own guard (security review Plugins-pack wave 2):
    # PostgreSQL settings, server control, XML exporters that run queries from a string,
    # notifications and sequence writes.
    "set_config",
    "current_setting",
    "query_to_xml_and_xmlschema",
    "query_to_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "database_to_xml",
    "database_to_xml_and_xmlschema",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_logical_emit_message",
    "pg_import_system_collations",
    "pg_current_logfile",
    "pg_notify",
    "nextval",
    "setval",
    # MySQL UDF shells, named locks, replication waits
    "sys_exec",
    "sys_eval",
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
    "master_pos_wait",
    "source_pos_wait",
    "uuid_short",
    # SQL Server file and log readers
    "fn_trace_gettable",
    "fn_xe_file_target_read_file",
    "fn_get_audit_file",
    "fn_dblog",
    "fn_dump_dblog",
    "openxml",
}

# Whole families refused per provider by name prefix (0.4.1, same lists as Qlar's guard):
# every PostgreSQL file/advisory-lock/large-object helper, every Oracle UTL_/DBMS_ package,
# every SQL Server extended or system procedure, every DuckDB reader or HTTP helper.
FORBIDDEN_PREFIXES: dict[str, tuple[str, ...]] = {
    "postgresql": (
        "pg_ls_", "pg_file_", "pg_sleep", "pg_advisory", "pg_try_advisory", "lo_", "dblink", "pg_stat_reset",
    ),
    "mysql": (),
    "oracle": ("utl_", "dbms_", "ordsys"),
    "sqlserver": ("xp_", "sp_"),
    "parquet": ("read_", "parquet_", "duckdb_secrets", "http"),
}

# SQL Server table hints that take or hold locks. A read-only gateway has no business blocking
# the customer's own writers (0.4.1).
LOCKING_TABLE_HINTS = {
    "updlock", "xlock", "tablock", "tablockx", "holdlock", "paglock", "serializable", "repeatableread",
}

# A textual backstop for constructs that are not a single function call and that some
# dialects parse into shapes the node check above would miss. Deliberately redundant with
# the AST checks: two nets with different holes catch more than either alone.
FORBIDDEN_PATTERNS = (
    re.compile(r"\bcopy\b.*\bfrom\s+program\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bcopy\b.*\bto\s+program\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\binto\s+(out|dump)file\b", re.IGNORECASE),
    re.compile(r"\bxp_\w+", re.IGNORECASE),
    re.compile(r"\bsp_oa\w+", re.IGNORECASE),
    re.compile(r"\bcreate\s+(or\s+replace\s+)?(function|procedure|trigger)\b", re.IGNORECASE),
)


class SqlRejected(Exception):
    """The statement was refused before it reached the database.

    Carries a `reason` short enough to log and to hand back to Qlar, which reports it as
    a security violation rather than a SQL error so that the calling agent does not try to
    "fix" the query and send it again.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def check(
    sql: str,
    provider: str,
    *,
    catalog_only: bool = False,
    allowlist: frozenset[str] = frozenset(),
) -> None:
    """Raises :class:`SqlRejected` unless the statement is a safe single read.

    Args:
        sql: the statement exactly as it will be sent to the driver.
        provider: one of the keys of :data:`DIALECTS`.
        catalog_only: an `introspect` job — every table must be a catalog object.
        allowlist: when non-empty, every table referenced must appear here.
    """
    if not sql or not sql.strip():
        raise SqlRejected("empty statement")

    dialect = DIALECTS.get(provider)
    if dialect is None:
        raise SqlRejected(f"unsupported provider {provider!r}")

    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(sql):
            raise SqlRejected(f"statement matches a forbidden construct: {pattern.pattern}")

    _reject_ambiguous_backslash(sql, provider)
    _reject_executable_comments(sql)

    try:
        statements = [statement for statement in sqlglot.parse(sql, dialect=dialect) if statement is not None]
    except Exception as error:  # sqlglot raises several unrelated types
        # Refusing unparseable SQL is a deliberate trade: a query this gateway cannot
        # understand is a query it cannot vouch for, and "Qlar produced SQL my parser
        # could not read" is a far better failure than running it blind.
        raise SqlRejected(f"statement could not be parsed: {error}") from error

    if len(statements) != 1:
        raise SqlRejected(f"expected exactly one statement, found {len(statements)}")

    statement = statements[0]
    _reject_forbidden_nodes(statement)
    _reject_non_select_root(statement)
    _reject_forbidden_functions(statement, provider)
    _reject_locking_hints(statement)
    if provider in PLAIN_TABLES_ONLY:
        _reject_file_access(statement)

    tables = referenced_tables(statement)
    if catalog_only:
        _require_catalog_only(tables, provider)
    elif allowlist:
        _require_allowlisted(tables, allowlist)


def _reject_forbidden_nodes(statement: exp.Expression) -> None:
    for node in statement.walk():
        if isinstance(node, FORBIDDEN_NODES):
            raise SqlRejected(f"{type(node).__name__.upper()} is not allowed; only read queries are")


def _reject_non_select_root(statement: exp.Expression) -> None:
    """Only a SELECT, a set operation over SELECTs, or a WITH ending in one."""
    root = statement
    if isinstance(root, exp.Subquery):
        root = root.unnest()

    allowed = (exp.Select, exp.Union, exp.Except, exp.Intersect)
    if not isinstance(root, allowed):
        raise SqlRejected(f"only SELECT statements are allowed, got {type(root).__name__.upper()}")


def _reject_ambiguous_backslash(sql: str, provider: str) -> None:
    """MySQL and PostgreSQL servers can each be configured to treat a backslash in a string as an
    escape or as a plain character (``NO_BACKSLASH_ESCAPES``, ``standard_conforming_strings``).
    Where a backslash sits in front of a quote, the parser and the server may then disagree on
    where the string ends, so the statement is refused rather than guessed at (0.4.1).
    """
    if provider in ("mysql", "postgresql") and "\\'" in sql:
        raise SqlRejected("a backslash in front of a quote is not allowed; servers disagree on what it means")


def _reject_executable_comments(sql: str) -> None:
    """MySQL runs the body of ``/*! ... */`` and reads ``/*+ ... */`` as optimizer hints. sqlglot
    treats both as comments, so a function hidden there would never reach the function check
    (0.4.1). Qlar strips every comment before it sends a statement, so a legitimate job never
    carries one.
    """
    if _EXECUTABLE_COMMENT.search(_blank_literals(sql)):
        raise SqlRejected("executable comments (/*! */, /*+ */) are not allowed")


_EXECUTABLE_COMMENT = re.compile(r"/\*[!+]")


def _blank_literals(sql: str) -> str:
    """The statement with the contents of quoted strings and identifiers replaced by spaces, so a
    textual check only sees SQL structure. Doubled quotes stay inside the literal; a backslash in
    front of a quote is refused before this runs where it would matter."""
    out: list[str] = []
    closing = {"'": "'", '"': '"', "`": "`", "[": "]"}
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in closing:
            end = closing[ch]
            out.append(ch)
            i += 1
            while i < n:
                if sql[i] == end:
                    if end != "]" and i + 1 < n and sql[i + 1] == end:
                        out.append("  ")
                        i += 2
                        continue
                    break
                out.append(" ")
                i += 1
            if i < n:
                out.append(sql[i])
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _reject_forbidden_functions(statement: exp.Expression, provider: str = "") -> None:
    prefixes = FORBIDDEN_PREFIXES.get(provider, ())
    for node in statement.find_all(exp.Func):
        name = _function_name(node)
        if name and name.lower() in FORBIDDEN_FUNCTIONS:
            raise SqlRejected(f"function {name} is not allowed")
        if name and prefixes and name.lower().startswith(prefixes):
            raise SqlRejected(f"function {name} is not allowed")

    # Package-qualified calls (Oracle's UTL_FILE.FOPEN, SQL Server's sys.xp_cmdshell)
    # arrive as dotted identifiers rather than as a function node, so check those too.
    for node in statement.find_all(exp.Dot):
        text = node.sql().lower()
        for forbidden in FORBIDDEN_FUNCTIONS:
            if text.startswith(f"{forbidden}.") or f".{forbidden}" in text:
                raise SqlRejected(f"function {forbidden} is not allowed")
        for part in text.replace('"', "").replace("[", "").replace("]", "").split("."):
            if prefixes and part.startswith(prefixes):
                raise SqlRejected(f"function {part} is not allowed")


    # Oracle package members read without parentheses (DBMS_RANDOM.VALUE, UTL_INADDR.GET_HOST_NAME)
    # parse as a column of a "table" named after the package. Only Oracle: elsewhere a table alias
    # such as lo_orders is ordinary.
    if provider == "oracle":
        for column in statement.find_all(exp.Column):
            qualifier = (column.table or "").lower()
            if qualifier and qualifier.startswith(prefixes):
                raise SqlRejected(f"package {column.table} is not allowed")


def _reject_locking_hints(statement: exp.Expression) -> None:
    """SQL Server ``WITH (UPDLOCK)`` and friends (0.4.1)."""
    hint_type = getattr(exp, "WithTableHint", None)
    if not isinstance(hint_type, type):
        return
    for hint in statement.find_all(hint_type):
        for item in hint.expressions:
            if item.sql().strip().lower().split("(")[0] in LOCKING_TABLE_HINTS:
                raise SqlRejected(f"table hint {item.sql()} takes a lock; only plain reads are allowed")


def _reject_file_access(statement: exp.Expression) -> None:
    """DuckDB only: every FROM item must be a table name, never a function or a path."""
    for node in statement.find_all(exp.Func):
        name = _function_name(node)
        if name and name.lower() in DUCKDB_FORBIDDEN_FUNCTIONS:
            raise SqlRejected(f"function {name} is not allowed; query the tables by name")

    for table in statement.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            raise SqlRejected("table functions are not allowed; query the tables by name")
        name = table.name
        if any(character in name for character in "./\\:*?"):
            raise SqlRejected(f"reading {name!r} by path is not allowed; query the tables by name")


def _function_name(node: exp.Func) -> str | None:
    if isinstance(node, exp.Anonymous):
        name = node.name
        return str(name) if name else None
    # Named function classes carry their SQL name on the class itself.
    sql_names = getattr(type(node), "sql_names", None)
    if callable(sql_names):
        names = sql_names()
        return str(names[0]) if names else None
    return None


def referenced_tables(statement: exp.Expression) -> set[str]:
    """Every real table the statement reads, lower-cased and schema-qualified.

    CTE names are excluded: `WITH recent AS (...) SELECT * FROM recent` reads `recent`
    from the query itself, not from the database, and treating it as a table would make
    every allowlist reject legitimate queries.
    """
    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}

    tables: set[str] = set()
    for table in statement.find_all(exp.Table):
        name = table.name.lower()
        if not name or name in cte_names:
            continue
        schema = (table.db or "").lower()
        tables.add(f"{schema}.{name}" if schema else name)
    return tables


def _require_catalog_only(tables: set[str], provider: str) -> None:
    catalog_schemas = CATALOG_SCHEMAS.get(provider, set())
    for table in tables:
        schema, _, bare = table.partition(".")
        if not bare:
            bare, schema = schema, ""

        if schema and schema in catalog_schemas:
            continue
        # PostgreSQL's system catalogs are on the default search_path, so catalog SQL refers to
        # `pg_constraint` rather than `pg_catalog.pg_constraint`. Requiring the qualification
        # would reject legitimate schema discovery — and `pg_catalog` is exactly where PK and FK
        # information has to come from, because information_schema hides constraints from anyone
        # who does not own the table, which a read-only account never does.
        if provider == "postgresql" and bare.startswith("pg_"):
            continue
        if provider == "oracle" and bare.startswith(ORACLE_CATALOG_PREFIXES):
            continue
        if provider == "sqlserver" and bare.startswith("sys"):
            continue
        raise SqlRejected(f"schema discovery may only read catalog objects, not {table}")


def _require_allowlisted(tables: set[str], allowlist: frozenset[str]) -> None:
    """Every referenced table must appear in the operator's allowlist.

    Matching has to work in both directions or the feature is unusable in practice: an
    operator naturally writes `public.hub` in their config, while the generated SQL just
    as naturally says `FROM hub`. So an entry matches when the qualified names are equal,
    when the query is unqualified and the bare names match, or when the entry itself was
    written unqualified.

    A *differently* qualified reference is still refused — `secret.hub` does not match an
    allowlist of `public.hub`. The residual gap is an unqualified reference, where the
    database's own `search_path` decides which schema is meant. If the same table name
    exists in several schemas and only one should be reachable, pin the search path on the
    database account rather than relying on this list.
    """
    bare_allowed = {entry.rpartition(".")[2] for entry in allowlist}

    for table in tables:
        if table in allowlist:
            continue

        schema, _, bare = table.partition(".")
        if not bare:  # the reference carried no schema
            bare, schema = schema, ""

        if not schema and bare in bare_allowed:
            continue
        if schema and bare in allowlist:  # the entry was written unqualified
            continue

        raise SqlRejected(f"table {table} is not in this gateway's TABLE_ALLOWLIST")
