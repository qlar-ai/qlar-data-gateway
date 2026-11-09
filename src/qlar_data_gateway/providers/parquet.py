"""Parquet provider: a folder of files, queried in-process with DuckDB.

Unlike the other providers there is no server here. The "connection" is a cursor on the
locked in-memory database built by `parquet_catalog`, the "read-only transaction" is that
lock plus the guard, and the statement timeout is a timer that interrupts the cursor -
DuckDB has no server-side statement timeout, and only an interrupt stops it using the
customer's CPU.

Error codes: DuckDB has no SQLSTATE or error number, so `driver_code` is the exception
class name (`BinderException`, `CatalogException`, ...). It is just as stable, and it is
what Qlar's log shows next to the message.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from ..config import DatabaseSettings
from .base import CATEGORY_CONNECTION, CATEGORY_SQL_ERROR, CATEGORY_TIMEOUT, DriverError

DEFAULT_PORT = None

# The statement was wrong; the model may rewrite it once with this message as feedback.
_SQL_ERRORS = (
    "ParserException",
    "SyntaxException",
    "BinderException",
    "CatalogException",
    "ConversionException",
    "TypeMismatchException",
    "OutOfRangeException",
    "InvalidInputException",
    "InvalidTypeException",
    "NotImplementedException",
    "ConstraintException",
)

# The files could not be read: missing, corrupt, or not permitted.
_SOURCE_ERRORS = ("IOException", "PermissionException", "HTTPException", "SerializationException")

# Messages are often several paragraphs of suggestions; the first part is what matters, and
# the whole message is handed back to a model as feedback.
_MAX_MESSAGE_CHARS = 1500


class _ParquetConnection:
    """Gives the executor the connection shape it expects, around one DuckDB cursor."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor
        self._timer: threading.Timer | None = None

    def cursor(self) -> Any:
        return self._cursor

    def arm_timeout(self, seconds: int) -> None:
        if seconds and seconds > 0:
            self._timer = threading.Timer(seconds, self._interrupt)
            self._timer.daemon = True
            self._timer.start()

    def _interrupt(self) -> None:
        try:
            self._cursor.interrupt()
        except Exception:  # noqa: S110 - the cursor may already be closed
            pass

    def rollback(self) -> None:
        # Nothing to roll back: the database is an in-memory set of views and the guard
        # admits nothing but a SELECT.
        return None

    def close(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        try:
            self._cursor.close()
        except Exception:  # noqa: S110 - deliberate best-effort cleanup
            pass


class ParquetProvider:
    name = "parquet"

    def connect(self, settings: DatabaseSettings) -> Any:
        from .. import parquet_catalog

        if settings.parquet is None:
            raise ValueError("DB_PROVIDER=parquet needs PARQUET_ROOT")
        catalog = parquet_catalog.get(settings.parquet)
        return _ParquetConnection(catalog.cursor())

    def begin_read_only(self, connection: Any, statement_timeout_seconds: int) -> Any:
        connection.arm_timeout(int(statement_timeout_seconds))
        return connection.cursor()

    def classify_error(self, error: BaseException) -> DriverError | None:
        try:
            import duckdb
        except ImportError:  # pragma: no cover - only when the extra is not installed
            return None

        from .. import parquet_catalog

        if isinstance(error, parquet_catalog.ParquetCatalogError):
            return DriverError(category=CATEGORY_CONNECTION, driver_code=None, message=str(error))

        if not isinstance(error, duckdb.Error):
            if isinstance(error, OSError):
                return DriverError(
                    category=CATEGORY_CONNECTION, driver_code=type(error).__name__, message=str(error)
                )
            return None

        code = type(error).__name__
        message = _message_of(error)

        if code == "InterruptException":
            return DriverError(
                category=CATEGORY_TIMEOUT,
                driver_code=code,
                message="the query ran longer than DB_STATEMENT_TIMEOUT_SECONDS and was stopped",
            )
        if code == "OutOfMemoryException":
            # Reported as a timeout on purpose: like a timeout it is "this query is too heavy
            # for the limits the customer set", and neither should be retried as is.
            return DriverError(
                category=CATEGORY_TIMEOUT,
                driver_code=code,
                message=f"the query needs more memory than PARQUET_MEMORY_LIMIT allows: {message}",
                hint="Filter on fewer rows or aggregate before returning detail.",
            )
        if code in _SOURCE_ERRORS:
            return DriverError(category=CATEGORY_CONNECTION, driver_code=code, message=message)
        if code == "FatalException":
            # The database is no longer usable; the next job builds a fresh one.
            parquet_catalog.invalidate()
            return DriverError(category=CATEGORY_CONNECTION, driver_code=code, message=message)
        if code in _SQL_ERRORS:
            return DriverError(category=CATEGORY_SQL_ERROR, driver_code=code, message=message)

        return DriverError(category=CATEGORY_SQL_ERROR, driver_code=code, message=message)

    def type_name(self, description_entry: Any) -> str:
        # DuckDB puts its own type object in the DB-API type_code slot; str() is the SQL name.
        return str(description_entry[1]) if description_entry and len(description_entry) > 1 else "unknown"

    def privilege_check_sql(self) -> str | None:
        # There is no account to inspect; `root_is_writable` asks the file system instead.
        return None

    @staticmethod
    def root_is_writable(settings: DatabaseSettings) -> bool | None:
        """Whether this process could change the Parquet files. None when unknown.

        Windows is skipped: `os.access` there only reflects the read-only attribute and
        would report almost every folder as writable.
        """
        if settings.parquet is None or os.name == "nt":
            return None
        return os.access(settings.parquet.root, os.W_OK)


def _message_of(error: BaseException) -> str:
    text = str(error).strip()
    return text if len(text) <= _MAX_MESSAGE_CHARS else text[:_MAX_MESSAGE_CHARS] + " ..."
