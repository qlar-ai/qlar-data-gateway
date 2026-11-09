"""Provider registry.

Each provider is imported lazily so that installing one database extra does not require
the other three drivers to be present — an on-premise install should only pull the driver
it actually uses.
"""

from __future__ import annotations

from .base import CATEGORY_CONNECTION, CATEGORY_SQL_ERROR, CATEGORY_TIMEOUT, DriverError, Provider

__all__ = [
    "CATEGORY_CONNECTION",
    "CATEGORY_SQL_ERROR",
    "CATEGORY_TIMEOUT",
    "DriverError",
    "Provider",
    "default_port",
    "get_provider",
]

# Module per provider, so one name is enough to reach either the class or its constants.
_PROVIDER_MODULES = {
    "postgresql": "postgres",
    "mysql": "mysql",
    "sqlserver": "sqlserver",
    "oracle": "oracle",
    "parquet": "parquet",
}


def get_provider(name: str) -> Provider:
    """Returns the provider for a name, raising a readable error for a missing driver."""
    key = (name or "").strip().lower()

    if key == "postgresql":
        from .postgres import PostgresProvider

        return _ensure_driver(PostgresProvider(), "psycopg[binary]", "postgresql")
    if key == "mysql":
        from .mysql import MySqlProvider

        return _ensure_driver(MySqlProvider(), "PyMySQL", "mysql")
    if key == "sqlserver":
        from .sqlserver import SqlServerProvider

        return _ensure_driver(SqlServerProvider(), "pymssql", "sqlserver")
    if key == "oracle":
        from .oracle import OracleProvider

        return _ensure_driver(OracleProvider(), "oracledb", "oracle")
    if key == "parquet":
        from .parquet import ParquetProvider

        return _ensure_driver(ParquetProvider(), "duckdb", "parquet")

    raise ValueError(f"unsupported provider {name!r}")


def default_port(name: str) -> int | None:
    """The port this provider uses when `DB_PORT` is not set, or None for an unknown name.

    Deliberately does not go through `get_provider`: the setup prompts offer a port default
    before anyone has installed a driver, and a missing driver must not stop them at the
    second question.
    """
    key = (name or "").strip().lower()
    if key not in _PROVIDER_MODULES:
        return None

    from importlib import import_module

    return import_module(f".{_PROVIDER_MODULES[key]}", __name__).DEFAULT_PORT


def _ensure_driver(provider: Provider, package: str, extra: str) -> Provider:
    """Turns a missing optional driver into an instruction rather than a traceback."""
    import importlib.util

    modules = {
        "postgresql": "psycopg",
        "mysql": "pymysql",
        "sqlserver": "pymssql",
        "oracle": "oracledb",
        "parquet": "duckdb",
    }
    module = modules[extra]
    if importlib.util.find_spec(module) is None:
        raise ImportError(
            f"the {extra} driver is not installed. Install it with: "
            f"pip install 'qlar-data-gateway[{extra}]'  (package: {package})"
        )
    return provider
