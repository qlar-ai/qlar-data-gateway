"""Turning a folder of Parquet files into tables DuckDB can query, and locking it down.

The gateway never hands DuckDB a path from Qlar. It decides on its own which files exist and
what each table is called, creates one VIEW per table over `read_parquet(...)`, and then
locks the database so that a statement can only ever read through those views:

* `allowed_directories` = the Parquet folder, `enable_external_access = false` - no file
  outside the folder can be opened, no database attached, no extension installed;
* `lock_configuration = true` - none of the above can be switched back by a statement.

Measured on DuckDB 2.0: `allowed_directories` permits *writing* inside the folder too
(`COPY ... TO '<root>/x.csv'` succeeds), and `read_parquet()` called directly inside the
folder works. Neither reaches a query here - the guard accepts only a single SELECT whose
tables are these views, and no table functions - but it is why the documentation asks for
the folder to be mounted read-only for the gateway's account.

How files become tables, in order:

1. every sub-folder directly in the root that contains `*.parquet` files (at any depth, so
   Hive-style `year=2025/month=01/` partitions work) is one table named after the folder;
2. every `*.parquet` file directly in the root is one table named after the file;
3. an optional tables file (JSON or TOML) can rename, add, exclude and describe tables and
   columns, or switch the automatic discovery off.

Names are lower-cased and anything outside `[a-z0-9_]` becomes `_`, so that the SQL Qlar
generates never needs quoting to name a table.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import ParquetSettings

logger = logging.getLogger(__name__)

# A re-scan on every introspect job would repeat itself three times in a row: Qlar sends
# tables, columns and foreign keys as three jobs. One scan per few seconds is enough.
REFRESH_MIN_INTERVAL_SECONDS = 10.0

_NAME_INVALID = re.compile(r"[^0-9a-z_]+")


class ParquetCatalogError(Exception):
    """The Parquet folder or tables file cannot be used as configured."""


@dataclass(frozen=True)
class TableSpec:
    """One table: a name, the files behind it, and optional descriptions."""

    name: str
    pattern: str  # absolute, forward slashes; a file or a glob
    hive_partitioning: bool = False
    description: str | None = None
    columns: dict[str, str] = field(default_factory=dict)


@dataclass
class ParquetCatalog:
    """A built, locked DuckDB database with one view per table."""

    connection: Any
    tables: list[TableSpec]
    problems: list[str]
    built_at: float
    duckdb_version: str

    @property
    def table_names(self) -> frozenset[str]:
        return frozenset(table.name for table in self.tables)

    def cursor(self) -> Any:
        # A DuckDB cursor is a separate connection to the same in-memory database: safe to
        # use from the worker thread that runs one job, and closed when the job ends.
        return self.connection.cursor()


def sanitize_name(raw: str) -> str:
    """`Sales 2025.parquet` -> `sales_2025`. Empty when nothing usable is left."""
    stem = raw[: -len(".parquet")] if raw.lower().endswith(".parquet") else raw
    name = _NAME_INVALID.sub("_", stem.strip().lower()).strip("_")
    if name and name[0].isdigit():
        name = f"t_{name}"
    return name


def discover(settings: ParquetSettings) -> tuple[list[TableSpec], list[str]]:
    """Works out the tables from the folder and the tables file. Opens no Parquet file."""
    root = Path(settings.root)
    if not root.is_dir():
        raise ParquetCatalogError(f"PARQUET_ROOT {root} does not exist or is not a folder")

    mapping = _load_tables_file(settings)
    problems: list[str] = []
    specs: dict[str, TableSpec] = {}

    auto = mapping.get("autoDiscover", mapping.get("auto_discover", True))
    excluded = {sanitize_name(str(name)) for name in mapping.get("exclude", [])}

    if auto:
        for entry in sorted(root.iterdir(), key=lambda path: path.name.lower()):
            if entry.name.startswith((".", "_")):
                continue  # hidden folders, Spark's _temporary, _SUCCESS markers
            if entry.is_dir():
                if not _contains_parquet(entry):
                    continue
                spec = TableSpec(
                    name=sanitize_name(entry.name),
                    pattern=f"{_posix(entry)}/**/*.parquet",
                    hive_partitioning=_looks_hive_partitioned(entry),
                )
            elif entry.is_file() and entry.name.lower().endswith(".parquet"):
                spec = TableSpec(name=sanitize_name(entry.name), pattern=_posix(entry))
            else:
                continue

            if not spec.name or spec.name in excluded:
                continue
            if spec.name in specs:
                problems.append(f"{entry.name}: another table is already called {spec.name}; skipped")
                continue
            specs[spec.name] = spec

    for raw_name, raw_table in (mapping.get("tables") or {}).items():
        name = sanitize_name(str(raw_name))
        if not name:
            problems.append(f"tables file: {raw_name!r} is not a usable table name; skipped")
            continue
        table = raw_table if isinstance(raw_table, dict) else {}
        existing = specs.get(name)

        path = table.get("path")
        if path:
            try:
                pattern, hive = _resolve_pattern(root, str(path))
            except ParquetCatalogError as error:
                problems.append(f"tables file: {raw_name}: {error}; skipped")
                continue
        elif existing is not None:
            pattern, hive = existing.pattern, existing.hive_partitioning
        else:
            problems.append(f"tables file: {raw_name} has no path and no folder of that name; skipped")
            continue

        columns = table.get("columns") or {}
        specs[name] = TableSpec(
            name=name,
            pattern=pattern,
            hive_partitioning=bool(table.get("hivePartitioning", table.get("hive_partitioning", hive))),
            description=_text_or_none(table.get("description"))
            or (existing.description if existing else None),
            columns={str(key): str(value) for key, value in columns.items() if str(value).strip()},
        )

    for name in excluded:
        specs.pop(name, None)

    return sorted(specs.values(), key=lambda spec: spec.name), problems


def build(settings: ParquetSettings) -> ParquetCatalog:
    """Creates the views, applies the descriptions, then locks the database."""
    import duckdb

    tables, problems = discover(settings)
    connection = duckdb.connect(":memory:")
    usable: list[TableSpec] = []

    for table in tables:
        view = _quote_identifier(table.name)
        source = (
            f"read_parquet({_quote_literal(table.pattern)}, "
            f"hive_partitioning = {'true' if table.hive_partitioning else 'false'}, union_by_name = true)"
        )
        try:
            # Binding the view reads each file's footer once - that is when a corrupt file
            # or a folder with no readable Parquet shows up, and it costs that one table,
            # not the whole gateway.
            connection.execute(f"CREATE VIEW {view} AS SELECT * FROM {source}")
            if table.description:
                connection.execute(f"COMMENT ON VIEW {view} IS {_quote_literal(table.description)}")
            for column, description in table.columns.items():
                try:
                    connection.execute(
                        f"COMMENT ON COLUMN {view}.{_quote_identifier(column)} "
                        f"IS {_quote_literal(description)}"
                    )
                except duckdb.Error:
                    problems.append(f"{table.name}: no column {column!r} to describe")
            usable.append(table)
        except duckdb.Error as error:
            problems.append(f"{table.name}: {_first_line(error)}")
            try:
                connection.execute(f"DROP VIEW IF EXISTS {view}")
            except duckdb.Error:  # pragma: no cover - best effort
                pass

    _lock_down(connection, settings)

    version = str(connection.execute("SELECT version()").fetchone()[0])
    for problem in problems:
        logger.warning("parquet: %s", problem)
    logger.info("parquet: %d table(s) from %s (DuckDB %s)", len(usable), settings.root, version)

    return ParquetCatalog(
        connection=connection,
        tables=usable,
        problems=problems,
        built_at=time.monotonic(),
        duckdb_version=version,
    )


def _lock_down(connection: Any, settings: ParquetSettings) -> None:
    """Resource limits first, then the access restrictions, then the lock - in that order,
    because once the configuration is locked nothing else can be set."""
    if settings.temp_dir:
        Path(settings.temp_dir).mkdir(parents=True, exist_ok=True)
        connection.execute(f"SET temp_directory = {_quote_literal(_posix(Path(settings.temp_dir)))}")
        connection.execute(f"SET max_temp_directory_size = {_quote_literal(settings.max_temp_size)}")
    connection.execute(f"SET memory_limit = {_quote_literal(settings.memory_limit)}")
    if settings.threads:
        connection.execute(f"SET threads = {int(settings.threads)}")
    # Without an ORDER BY the row order is undefined anyway; not preserving it lets large
    # aggregations and exports stream instead of buffering.
    connection.execute("SET preserve_insertion_order = false")

    root = _posix(Path(settings.root))
    connection.execute(f"SET allowed_directories = [{_quote_literal(root + '/')}]")
    connection.execute("SET enable_external_access = false")
    connection.execute("SET autoinstall_known_extensions = false")
    connection.execute("SET autoload_known_extensions = false")
    connection.execute("SET lock_configuration = true")


# --------------------------------------------------------------------------- the cache


_lock = threading.Lock()
_current: ParquetCatalog | None = None
_current_key: ParquetSettings | None = None


def get(settings: ParquetSettings) -> ParquetCatalog:
    """The catalog for these settings, built on first use."""
    global _current, _current_key
    with _lock:
        if _current is None or _current_key != settings:
            _current = build(settings)
            _current_key = settings
        return _current


def refresh(settings: ParquetSettings, *, force: bool = False) -> ParquetCatalog:
    """Re-scans the folder so new tables and columns appear, at most every few seconds.

    A new database replaces the old one rather than altering it: the old one is locked, and
    a job still running on it keeps its own reference until it finishes.
    """
    global _current, _current_key
    with _lock:
        fresh_enough = (
            _current is not None
            and _current_key == settings
            and time.monotonic() - _current.built_at < REFRESH_MIN_INTERVAL_SECONDS
        )
        if force or not fresh_enough:
            _current = build(settings)
            _current_key = settings
        return _current


def invalidate() -> None:
    """Forgets the catalog, e.g. after DuckDB reported a fatal error."""
    global _current, _current_key
    with _lock:
        _current = None
        _current_key = None


# --------------------------------------------------------------------------- helpers


def _load_tables_file(settings: ParquetSettings) -> dict[str, Any]:
    if not settings.tables_file:
        return {}

    path = Path(settings.tables_file).expanduser()
    if not path.is_absolute():
        path = Path(settings.root) / path
    if not path.is_file():
        raise ParquetCatalogError(f"PARQUET_TABLES_FILE {path} does not exist")

    text = path.read_text(encoding="utf-8-sig")
    try:
        if path.suffix.lower() == ".toml":
            import tomllib

            data = tomllib.loads(text)
        else:
            data = json.loads(text)
    except (ValueError, TypeError) as error:
        raise ParquetCatalogError(f"PARQUET_TABLES_FILE {path} cannot be parsed: {error}") from error

    if not isinstance(data, dict):
        raise ParquetCatalogError(f"PARQUET_TABLES_FILE {path} must contain an object at the top level")
    return data


def _resolve_pattern(root: Path, path: str) -> tuple[str, bool]:
    """A tables-file path, made absolute and proven to stay inside the root."""
    if ".." in Path(path).parts:
        raise ParquetCatalogError(f"path {path!r} may not contain '..'")

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate

    # Only the part before the first wildcard can be resolved on disk.
    parts = candidate.parts
    fixed_parts: list[str] = []
    for part in parts:
        if any(character in part for character in "*?["):
            break
        fixed_parts.append(part)
    fixed = Path(*fixed_parts).resolve() if fixed_parts else root.resolve()
    root_resolved = root.resolve()
    if fixed != root_resolved and root_resolved not in fixed.parents:
        raise ParquetCatalogError(f"path {path!r} is outside PARQUET_ROOT")

    if candidate.is_dir():
        return f"{_posix(candidate.resolve())}/**/*.parquet", _looks_hive_partitioned(candidate)
    if candidate.is_file():
        return _posix(candidate.resolve()), False
    if fixed_parts == list(parts):
        raise ParquetCatalogError(f"path {path!r} does not exist")
    return _posix(candidate), False


def _contains_parquet(folder: Path) -> bool:
    for _dirpath, _dirnames, filenames in os.walk(folder):
        if any(name.lower().endswith(".parquet") for name in filenames):
            return True
    return False


def _looks_hive_partitioned(folder: Path) -> bool:
    try:
        return any(child.is_dir() and "=" in child.name for child in folder.iterdir())
    except OSError:
        return False


def _posix(path: Path) -> str:
    return str(path).replace("\\", "/").rstrip("/")


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _text_or_none(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _first_line(error: BaseException) -> str:
    return (str(error).strip().splitlines() or [type(error).__name__])[0]
