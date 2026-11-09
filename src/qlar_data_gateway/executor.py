"""Running one job against the local database.

Everything a job touches happens here: the guard runs, a connection is opened, the
statement executes inside a read-only transaction with a deadline, the rows are encoded,
and the transaction is rolled back — always rolled back, never committed, because a read
has nothing to commit and a rollback is the cheapest way to guarantee that.

Failures are described, not interpreted. The driver's own error code travels back to Qlar
untouched so that Qlar's classifier — which deliberately keys on codes, never on message
text — can decide whether the agent should retry with corrected SQL or be told the data
source is unreachable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .config import DatabaseSettings
from .encoding import TruncationReason, column_descriptors, encode_rows
from .guard import SqlRejected
from .guard import check as guard_check
from .providers import CATEGORY_CONNECTION, CATEGORY_SQL_ERROR, DriverError, get_provider

# What a job asks for when it does not say. Mirrors the direct path's own default.
DEFAULT_MAX_ROWS = 1000


@dataclass
class ExecutionResult:
    """The outcome of one job, in the shape the result endpoint expects."""

    status: str  # "ok" | "error"
    columns: list[dict[str, str]] | None = None
    rows: list[list[Any]] | None = None
    row_count: int = 0
    truncated: bool = False
    truncation_reason: str | None = None
    duration_ms: int = 0
    error: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        if self.status == "ok":
            return {
                "status": "ok",
                "columns": self.columns or [],
                "rows": self.rows or [],
                "rowCount": self.row_count,
                "truncated": self.truncated,
                "truncationReason": self.truncation_reason,
                "durationMs": self.duration_ms,
            }
        return {"status": "error", "error": self.error or {}, "durationMs": self.duration_ms}


def execute(
    sql: str,
    settings: DatabaseSettings,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    catalog_only: bool = False,
) -> ExecutionResult:
    """Guards, runs and encodes one statement. Never raises for an expected failure."""
    started = time.monotonic()
    provider = None

    try:
        provider = get_provider(settings.provider)
    except (ValueError, ImportError) as error:
        return _failure(CATEGORY_CONNECTION, None, str(error), started)

    allowlist = frozenset() if catalog_only else settings.table_allowlist
    if settings.is_file_source:
        try:
            allowlist = _file_source_allowlist(settings, catalog_only=catalog_only)
        except Exception as error:  # noqa: BLE001 - a folder that cannot be read is a payload
            described = provider.classify_error(error) or DriverError(
                category=CATEGORY_CONNECTION, driver_code=None, message=f"{type(error).__name__}: {error}"
            )
            return _failure(described.category, described.driver_code, described.message, started)
        if not catalog_only and not allowlist:
            return _failure(
                "rejected",
                None,
                "no tables were found in PARQUET_ROOT (or none survive TABLE_ALLOWLIST)",
                started,
            )

    try:
        guard_check(
            sql,
            settings.provider,
            catalog_only=catalog_only,
            # A schema-discovery job is confined to catalog objects instead, which the
            # customer's table allowlist would otherwise reject outright.
            allowlist=allowlist,
        )
    except SqlRejected as rejection:
        # Its own category: this is not the database refusing a statement, so Qlar must not
        # feed it back to the model as something to "repair" — it would just try again.
        return _failure("rejected", None, rejection.reason, started)

    connection = None
    try:
        connection = provider.connect(settings)
        cursor = provider.begin_read_only(connection, settings.statement_timeout_seconds)

        cursor.execute(sql)

        # One row beyond the ceiling, so that "there was more" can be reported rather than
        # silently truncating — the same contract the direct path honours.
        columns = column_descriptors(cursor, provider.type_name)
        rows, reason = encode_rows(cursor, max_rows + 1, settings.max_result_bytes)

        exceeded_rows = len(rows) > max_rows
        if exceeded_rows:
            rows = rows[:max_rows]

        truncated = exceeded_rows or reason == TruncationReason.BYTE_LIMIT
        truncation_reason = (
            TruncationReason.BYTE_LIMIT
            if reason == TruncationReason.BYTE_LIMIT
            else (TruncationReason.ROW_LIMIT if exceeded_rows else None)
        )

        return ExecutionResult(
            status="ok",
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=truncated,
            truncation_reason=truncation_reason,
            duration_ms=_elapsed_ms(started),
        )

    except BaseException as error:  # noqa: BLE001 - every failure must become a payload
        described = provider.classify_error(error) if provider else None
        if described is None:
            described = DriverError(
                category=CATEGORY_SQL_ERROR,
                driver_code=None,
                message=f"{type(error).__name__}: {error}".strip(),
            )
        return ExecutionResult(
            status="error",
            duration_ms=_elapsed_ms(started),
            error={
                "category": described.category,
                "driverCode": described.driver_code,
                "messageText": described.message,
                "hint": described.hint,
                "position": described.position,
            },
        )

    finally:
        if connection is not None:
            # Rolled back rather than committed: a read has nothing to commit, and this
            # holds even on the error path where the transaction may be mid-statement.
            try:
                connection.rollback()
            except Exception:  # noqa: S110 - deliberate best-effort cleanup
                pass
            try:
                connection.close()
            except Exception:  # noqa: S110 - deliberate best-effort cleanup
                pass


def test_connection(settings: DatabaseSettings) -> ExecutionResult:
    """Opens a connection and reports the server version, for the setup wizard."""
    started = time.monotonic()

    try:
        provider = get_provider(settings.provider)
    except (ValueError, ImportError) as error:
        return _failure(CATEGORY_CONNECTION, None, str(error), started)

    probes = {
        "postgresql": "SELECT version()",
        "mysql": "SELECT VERSION()",
        "sqlserver": "SELECT @@VERSION",
        "oracle": "SELECT banner FROM v$version WHERE ROWNUM = 1",
    }

    connection = None
    try:
        if settings.is_file_source:
            version = _describe_file_source(settings)
        else:
            connection = provider.connect(settings)
            cursor = connection.cursor()
            cursor.execute(probes[settings.provider])
            record = cursor.fetchone()
            version = str(record[0]) if record else ""

        return ExecutionResult(
            status="ok",
            columns=[{"name": "version", "type": "text"}],
            rows=[[version]],
            row_count=1,
            duration_ms=_elapsed_ms(started),
        )
    except BaseException as error:  # noqa: BLE001
        described = provider.classify_error(error) or DriverError(
            category=CATEGORY_CONNECTION,
            driver_code=None,
            message=f"{type(error).__name__}: {error}".strip(),
        )
        return ExecutionResult(
            status="error",
            duration_ms=_elapsed_ms(started),
            error={
                "category": described.category,
                "driverCode": described.driver_code,
                "messageText": described.message,
                "hint": described.hint,
                "position": described.position,
            },
        )
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:  # noqa: S110 - deliberate best-effort cleanup
                pass


def account_can_write(settings: DatabaseSettings) -> bool | None:
    """Best-effort check for an over-privileged database account.

    Returns True when the account looks able to write, False when it does not, and None
    when the check could not be made. Advisory only — it is a warning at startup, never a
    reason to refuse to run, because a customer may have perfectly good reasons for the
    grant they chose and should not be locked out by our opinion.
    """
    try:
        provider = get_provider(settings.provider)
        if settings.is_file_source:
            # No account to ask; whether this process could change the files is the same
            # question asked of the file system.
            return provider.root_is_writable(settings)

        sql = provider.privilege_check_sql()
        if sql is None:
            return None

        connection = provider.connect(settings)
        try:
            cursor = connection.cursor()
            cursor.execute(sql)
            record = cursor.fetchone()
            if record is None:
                return None

            value = record[0]
            if isinstance(value, bool):
                return value
            if isinstance(value, int):
                return value > 0
            # MySQL's SHOW GRANTS returns text; look for anything beyond SELECT.
            text = str(value).upper()
            write_words = ("ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP")
            return any(word in text for word in write_words)
        finally:
            connection.close()
    except Exception:
        return None


def _file_source_allowlist(settings: DatabaseSettings, *, catalog_only: bool) -> frozenset[str]:
    """The tables a Parquet job may read: the discovered views, narrowed by TABLE_ALLOWLIST.

    Unlike a database, where the allowlist is an optional extra, here it is always on: the
    views are the only things a statement may name, because anything else in a DuckDB FROM
    clause is a way to read a file. A schema-discovery job re-scans the folder first, which
    is how a new folder becomes a new table on "Refresh Schema".
    """
    from . import parquet_catalog

    if settings.parquet is None:
        raise ValueError("DB_PROVIDER=parquet needs PARQUET_ROOT")

    if catalog_only:
        parquet_catalog.refresh(settings.parquet)
        return frozenset()

    names = parquet_catalog.get(settings.parquet).table_names
    if not settings.table_allowlist:
        return names
    operator = {entry.rpartition(".")[2] for entry in settings.table_allowlist}
    return frozenset(name for name in names if name in operator)


def _describe_file_source(settings: DatabaseSettings) -> str:
    """`DuckDB v2.0.0 - 3 tables in /data/parquet (1 skipped)`, re-scanning the folder."""
    from . import parquet_catalog

    if settings.parquet is None:
        raise ValueError("DB_PROVIDER=parquet needs PARQUET_ROOT")

    catalog = parquet_catalog.refresh(settings.parquet, force=True)
    count = len(catalog.tables)
    tables = f"{count} table{'s' if count != 1 else ''}"
    text = f"DuckDB {catalog.duckdb_version} - {tables} in {settings.parquet.root}"
    if catalog.problems:
        text += f" ({len(catalog.problems)} skipped: {catalog.problems[0]})"
    return text


def _failure(category: str, code: str | None, message: str, started: float) -> ExecutionResult:
    return ExecutionResult(
        status="error",
        duration_ms=_elapsed_ms(started),
        error={
            "category": category,
            "driverCode": code,
            "messageText": message,
            "hint": None,
            "position": None,
        },
    )


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
