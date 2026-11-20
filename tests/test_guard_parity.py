"""0.4.1: the gateway refuses everything Qlar's own guard refuses (security review Plugins-pack wave 2).

Qlar validates before it sends, so in normal operation none of these reach the gateway. They are
here for the case this module is written for: a Qlar that can no longer be trusted.
"""

from __future__ import annotations

import pytest

from qlar_data_gateway.guard import SqlRejected, check


def rejected(sql: str, provider: str) -> str:
    with pytest.raises(SqlRejected) as caught:
        check(sql, provider)
    return caught.value.reason


class TestExecutableComments:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1 /*!, (SELECT LOAD_FILE('/etc/passwd')) */",
            "SELECT /*!50000 SLEEP(5) */ 1",
            "SELECT /*+ MAX_EXECUTION_TIME(1) */ id FROM t",
            "SELECT 1 /* ! spaced */",
        ],
    )
    def test_mysql_executable_and_hint_comments_are_refused(self, sql):
        if "! spaced" in sql:
            check(sql, "mysql")  # a plain comment that merely contains "!" later is fine
            return
        assert "executable comments" in rejected(sql, "mysql")

    def test_the_marker_inside_a_string_is_not_a_comment(self):
        check("SELECT '/*! not a comment */' AS x FROM t", "mysql")
        check("SELECT 'it''s /*+ fine */' AS x FROM t", "postgresql")


class TestAmbiguousBackslash:
    @pytest.mark.parametrize("provider", ["mysql", "postgresql"])
    def test_backslash_before_quote_is_refused(self, provider):
        assert "backslash" in rejected("SELECT 'a\\' OR 1=1 --' AS x FROM t", provider)

    def test_sql_server_keeps_backslashes(self):
        check("SELECT 'C:\\path\\' AS x FROM t", "sqlserver")

    def test_a_backslash_elsewhere_is_fine(self):
        check("SELECT 'a\\b' AS x FROM t", "postgresql")


class TestMoreForbiddenFunctions:
    @pytest.mark.parametrize(
        ("sql", "provider"),
        [
            ("SELECT set_config('role', 'admin', false)", "postgresql"),
            ("SELECT current_setting('data_directory')", "postgresql"),
            ("SELECT pg_ls_waldir()", "postgresql"),
            ("SELECT pg_advisory_lock(1)", "postgresql"),
            ("SELECT lo_get(1)", "postgresql"),
            ("SELECT nextval('orders_id_seq')", "postgresql"),
            ("SELECT pg_notify('ch', 'x')", "postgresql"),
            ("SELECT query_to_xml('select 1', true, true, '')", "postgresql"),
            ("SELECT sys_exec('id')", "mysql"),
            ("SELECT GET_LOCK('x', 10)", "mysql"),
            ("SELECT * FROM fn_dblog(NULL, NULL)", "sqlserver"),
            ("SELECT * FROM sys.fn_get_audit_file('x', default, default)", "sqlserver"),
            ("SELECT DBMS_UTILITY.GET_TIME FROM dual", "oracle"),
            ("SELECT * FROM iceberg_scan('s3://bucket/t')", "parquet"),
        ],
    )
    def test_refused(self, sql, provider):
        assert "not allowed" in rejected(sql, provider)

    def test_ordinary_functions_still_pass(self):
        check("SELECT lower(name), count(*) FROM customers GROUP BY lower(name)", "postgresql")
        check("SELECT TOP 5 name, SUM(total) AS s FROM orders GROUP BY name ORDER BY s DESC", "sqlserver")
        check("SELECT name, NVL(city, '-') FROM customers FETCH FIRST 5 ROWS ONLY", "oracle")


class TestLockingReads:
    @pytest.mark.parametrize(
        ("sql", "provider"),
        [
            ("SELECT id FROM orders FOR UPDATE", "postgresql"),
            ("SELECT id FROM orders FOR SHARE", "postgresql"),
            ("SELECT id FROM orders FOR UPDATE", "mysql"),
            ("SELECT id FROM orders WITH (UPDLOCK)", "sqlserver"),
            ("SELECT id FROM orders WITH (HOLDLOCK)", "sqlserver"),
        ],
    )
    def test_refused(self, sql, provider):
        rejected(sql, provider)

    def test_nolock_hint_is_a_plain_read(self):
        check("SELECT id FROM orders WITH (NOLOCK)", "sqlserver")
