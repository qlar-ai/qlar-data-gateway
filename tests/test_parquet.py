"""Parquet provider: folders become tables, and nothing but those tables can be read.

The threat list here is DuckDB-specific. In a DuckDB FROM clause almost anything that is
not a table is a way to read a file - `read_parquet(...)`, `read_csv(...)`, `glob(...)`,
`query('...')`, or just `FROM 'file.parquet'` - and `allowed_directories` alone was measured
to permit writing inside the folder. So the tests prove both halves: honest analytics works,
and every one of those escape hatches is refused before DuckDB sees it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

duckdb = pytest.importorskip("duckdb")

from qlar_data_gateway import parquet_catalog  # noqa: E402
from qlar_data_gateway.config import ConfigError, DatabaseSettings, ParquetSettings, load_settings  # noqa: E402
from qlar_data_gateway.executor import account_can_write, execute  # noqa: E402
from qlar_data_gateway.executor import test_connection as probe_connection  # noqa: E402


def _posix(path: Path) -> str:
    return str(path).replace("\\", "/")


def _write(sql: str) -> None:
    connection = duckdb.connect()
    try:
        connection.execute(sql)
    finally:
        connection.close()


@pytest.fixture(autouse=True)
def fresh_catalog():
    parquet_catalog.invalidate()
    yield
    parquet_catalog.invalidate()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """sales/ partitioned by year, stores.parquet at the root, plus noise to ignore."""
    data = tmp_path / "data"
    for year in (2024, 2025):
        folder = data / "Sales" / f"year={year}"
        folder.mkdir(parents=True)
        _write(
            f"COPY (SELECT range AS id, range % 3 AS store_id, (range * 1.5)::DECIMAL(10,2) AS amount, "
            f"TIMESTAMPTZ '2025-01-01 10:00:00+07' AS sold_at FROM range(100)) "
            f"TO '{_posix(folder)}/part-0.parquet' (FORMAT parquet)"
        )
    _write(
        f"COPY (SELECT * FROM (VALUES (0, 'Jakarta'), (1, 'Surabaya'), (2, 'Medan')) t(store_id, city)) "
        f"TO '{_posix(data)}/Stores.parquet' (FORMAT parquet)"
    )
    (data / "_temporary").mkdir()
    (data / ".hidden").mkdir()
    (data / "notes.txt").write_text("not a table", encoding="utf-8")
    (data / "empty_folder").mkdir()
    return data


def settings_for(root: Path, tmp_path: Path, **overrides) -> DatabaseSettings:
    parquet = ParquetSettings(
        root=str(root),
        temp_dir=str(tmp_path / "spill"),
        memory_limit=overrides.pop("memory_limit", "512MB"),
        threads=overrides.pop("threads", 2),
        tables_file=overrides.pop("tables_file", ""),
    )
    return DatabaseSettings(
        provider="parquet",
        host="",
        port=None,
        database="",
        user="",
        password="",
        statement_timeout_seconds=overrides.pop("statement_timeout_seconds", 30),
        table_allowlist=overrides.pop("table_allowlist", frozenset()),
        parquet=parquet,
    )


class TestDiscovery:
    def test_folders_and_root_files_become_tables(self, root, tmp_path):
        tables, problems = parquet_catalog.discover(settings_for(root, tmp_path).parquet)

        assert [table.name for table in tables] == ["sales", "stores"]
        sales = tables[0]
        assert sales.hive_partitioning is True
        assert sales.pattern.endswith("/Sales/**/*.parquet")
        assert problems == []

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Sales 2025.parquet", "sales_2025"),
            ("order-items", "order_items"),
            ("2025_sales", "t_2025_sales"),
            ("---", ""),
        ],
    )
    def test_names_never_need_quoting(self, raw, expected):
        assert parquet_catalog.sanitize_name(raw) == expected

    def test_two_sources_with_one_name_keep_the_first(self, root, tmp_path):
        _write(f"COPY (SELECT 1 AS a) TO '{_posix(root)}/sales.parquet' (FORMAT parquet)")

        tables, problems = parquet_catalog.discover(settings_for(root, tmp_path).parquet)

        assert [table.name for table in tables] == ["sales", "stores"]
        assert any("already called sales" in problem for problem in problems)

    def test_tables_file_renames_describes_and_excludes(self, root, tmp_path):
        mapping = root / "tables.json"
        mapping.write_text(
            json.dumps(
                {
                    "exclude": ["stores"],
                    "tables": {
                        "sales": {"description": "One row per sale", "columns": {"amount": "Gross, in IDR"}},
                        "branches": {"path": "Stores.parquet", "description": "Branch list"},
                    },
                }
            ),
            encoding="utf-8",
        )

        tables, problems = parquet_catalog.discover(
            settings_for(root, tmp_path, tables_file="tables.json").parquet
        )

        by_name = {table.name: table for table in tables}
        assert set(by_name) == {"sales", "branches"}
        assert by_name["sales"].description == "One row per sale"
        assert by_name["sales"].columns == {"amount": "Gross, in IDR"}
        assert by_name["branches"].pattern.endswith("/Stores.parquet")
        assert problems == []

    def test_tables_file_toml(self, root, tmp_path):
        (root / "tables.toml").write_text(
            'auto_discover = false\n[tables.shop]\npath = "Stores.parquet"\ndescription = "Shops"\n',
            encoding="utf-8",
        )

        tables, _ = parquet_catalog.discover(settings_for(root, tmp_path, tables_file="tables.toml").parquet)

        assert [(table.name, table.description) for table in tables] == [("shop", "Shops")]

    @pytest.mark.parametrize("path", ["../outside", "/etc", "C:/Windows"])
    def test_tables_file_cannot_point_outside_the_root(self, root, tmp_path, path):
        (root / "tables.json").write_text(json.dumps({"tables": {"evil": {"path": path}}}), encoding="utf-8")

        tables, problems = parquet_catalog.discover(
            settings_for(root, tmp_path, tables_file="tables.json").parquet
        )

        assert "evil" not in {table.name for table in tables}
        assert any("evil" in problem for problem in problems)


class TestQueries:
    def test_aggregate_across_partitions_and_join(self, root, tmp_path):
        result = execute(
            "SELECT s.city, t.year, COUNT(*) AS sales, SUM(t.amount) AS total "
            "FROM sales t JOIN stores s ON s.store_id = t.store_id "
            "GROUP BY ALL ORDER BY s.city, t.year",
            settings_for(root, tmp_path),
        )

        assert result.status == "ok", result.error
        assert result.columns[0]["name"] == "city"
        assert result.columns[0]["type"] in ("VARCHAR", "STRING")  # DuckDB 1.2 says STRING
        assert result.rows[0][:3] == ["Jakarta", 2024, 34]
        assert isinstance(result.rows[0][3], str)  # DECIMAL travels as a string

    def test_timestamptz_is_returned(self, root, tmp_path):
        result = execute("SELECT sold_at FROM sales LIMIT 1", settings_for(root, tmp_path))

        assert result.status == "ok", result.error
        assert result.rows[0][0].startswith("2025-01-01")

    def test_row_limit_is_reported(self, root, tmp_path):
        result = execute("SELECT id FROM sales", settings_for(root, tmp_path), max_rows=10)

        assert result.row_count == 10
        assert result.truncated is True
        assert result.truncation_reason == "row_limit"

    def test_wrong_column_is_a_sql_error_the_model_can_repair(self, root, tmp_path):
        result = execute("SELECT revenu FROM sales", settings_for(root, tmp_path))

        assert result.status == "error"
        assert result.error["category"] == "sql_error"
        assert result.error["driverCode"] == "BinderException"
        assert "revenu" in result.error["messageText"]

    def test_slow_query_is_interrupted_as_a_timeout(self, root, tmp_path):
        result = execute(
            "SELECT COUNT(*) FROM sales a, sales b, sales c, sales d, sales e "
            "WHERE a.id + b.id + c.id + d.id > e.id",
            settings_for(root, tmp_path, statement_timeout_seconds=1),
        )

        assert result.status == "error"
        assert result.error["category"] == "timeout"
        assert result.error["driverCode"] == "InterruptException"
        assert result.duration_ms < 15_000

    def test_operator_allowlist_narrows_the_tables(self, root, tmp_path):
        settings = settings_for(root, tmp_path, table_allowlist=frozenset({"stores"}))

        assert execute("SELECT * FROM stores", settings).status == "ok"
        refused = execute("SELECT * FROM sales", settings)
        assert refused.error["category"] == "rejected"

    def test_introspection_reads_the_catalog_with_descriptions(self, root, tmp_path):
        (root / "tables.json").write_text(
            json.dumps({"tables": {"sales": {"description": "Sales", "columns": {"amount": "Gross"}}}}),
            encoding="utf-8",
        )
        settings = settings_for(root, tmp_path, tables_file="tables.json")

        tables = execute(
            "SELECT table_name, TABLE_COMMENT FROM information_schema.tables ORDER BY 1",
            settings,
            catalog_only=True,
        )
        columns = execute(
            "SELECT column_name, data_type, COLUMN_COMMENT FROM information_schema.columns "
            "WHERE table_name = 'sales' ORDER BY ordinal_position",
            settings,
            catalog_only=True,
        )

        assert tables.rows == [["sales", "Sales"], ["stores", None]]
        assert ["amount", "DECIMAL(10,2)", "Gross"] in columns.rows
        assert ["year", "BIGINT", None] in columns.rows

    def test_a_new_folder_appears_after_introspection(self, root, tmp_path):
        settings = settings_for(root, tmp_path)
        assert execute("SELECT 1 FROM stores", settings).status == "ok"

        folder = root / "returns"
        folder.mkdir()
        _write(f"COPY (SELECT 1 AS id) TO '{_posix(folder)}/r.parquet' (FORMAT parquet)")
        parquet_catalog.refresh(settings.parquet, force=True)

        assert execute("SELECT * FROM returns", settings).rows == [[1]]

    def test_a_corrupt_table_costs_only_that_table(self, root, tmp_path):
        broken = root / "broken"
        broken.mkdir()
        (broken / "x.parquet").write_bytes(b"not parquet at all")

        catalog = parquet_catalog.get(settings_for(root, tmp_path).parquet)

        assert catalog.table_names == {"sales", "stores"}
        assert any(problem.startswith("broken:") for problem in catalog.problems)


class TestEscapeHatchesAreRefused:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM read_parquet('/etc/*.parquet')",
            "SELECT * FROM read_csv('C:/secret.csv')",
            "SELECT * FROM read_text('/etc/passwd')",
            "SELECT * FROM 'Stores.parquet'",
            'SELECT * FROM "Stores.parquet"',
            "SELECT * FROM glob('*')",
            "SELECT * FROM sales s JOIN query('SELECT 1') q ON true",
            "SELECT * FROM sales, range(10)",
            "SELECT getenv('HOME')",
            "SELECT * FROM information_schema.tables",
            "SELECT * FROM unknown_table",
            "COPY (SELECT 1) TO 'out.csv'",
            "ATTACH 'other.db'",
            "PRAGMA show_tables",
            "INSTALL httpfs",
            "SET enable_external_access = true",
            "CREATE VIEW x AS SELECT 1",
            "SELECT 1; SELECT 2",
        ],
    )
    def test_refused_before_duckdb(self, root, tmp_path, sql):
        result = execute(sql, settings_for(root, tmp_path))

        assert result.status == "error"
        assert result.error["category"] == "rejected", result.error

    def test_introspection_may_not_read_data(self, root, tmp_path):
        result = execute("SELECT * FROM sales", settings_for(root, tmp_path), catalog_only=True)

        assert result.error["category"] == "rejected"

    def test_the_lock_holds_even_without_the_guard(self, root, tmp_path):
        outside = tmp_path / "outside.csv"
        outside.write_text("a\n1\n", encoding="utf-8")
        cursor = parquet_catalog.get(settings_for(root, tmp_path).parquet).cursor()

        with pytest.raises(duckdb.Error):
            cursor.execute(f"SELECT * FROM read_csv('{_posix(outside)}')")
        with pytest.raises(duckdb.Error):
            cursor.execute("SET lock_configuration = false")
        with pytest.raises(duckdb.Error):
            cursor.execute("SET enable_external_access = true")


class TestConnectionAndSettings:
    def test_test_connection_reports_engine_and_tables(self, root, tmp_path):
        result = probe_connection(settings_for(root, tmp_path))

        assert result.status == "ok", result.error
        assert result.rows[0][0].startswith("DuckDB v")
        assert "2 tables in" in result.rows[0][0]

    def test_missing_root_is_a_connection_failure(self, tmp_path):
        settings = settings_for(tmp_path / "gone", tmp_path)

        assert probe_connection(settings).error["category"] == "connection"
        assert execute("SELECT 1 FROM sales", settings).error["category"] == "connection"

    def test_load_settings_needs_only_a_folder(self, root, tmp_path, monkeypatch):
        for key in (
            "DB_HOST",
            "DB_NAME",
            "DB_USER",
            "DB_PASSWORD",
            "MAX_CONCURRENT_QUERIES",
            "PARQUET_THREADS",
        ):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("QLAR_BASE_URL", "https://localhost/api/data-gateway")
        monkeypatch.setenv("DB_PROVIDER", "parquet")
        monkeypatch.setenv("PARQUET_ROOT", str(root))
        monkeypatch.setenv("GATEWAY_STATE_FILE", str(tmp_path / "state" / "gateway-state.json"))

        settings = load_settings(None)

        assert settings.database.parquet.root == str(root.resolve())
        assert settings.database.parquet.memory_limit == "50%"
        assert settings.database.parquet.temp_dir == str((tmp_path / "state" / "duckdb-tmp").resolve())
        assert settings.max_concurrent_queries == 1
        assert settings.database.describe() == f"parquet://{root.resolve()}"

    def test_load_settings_rejects_a_missing_folder(self, tmp_path, monkeypatch):
        monkeypatch.setenv("QLAR_BASE_URL", "https://localhost/api/data-gateway")
        monkeypatch.setenv("DB_PROVIDER", "parquet")
        monkeypatch.setenv("PARQUET_ROOT", str(tmp_path / "nope"))

        with pytest.raises(ConfigError, match="PARQUET_ROOT"):
            load_settings(None)

    def test_write_check_does_not_fail(self, root, tmp_path):
        assert account_can_write(settings_for(root, tmp_path)) in (True, False, None)
