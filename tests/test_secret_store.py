"""The database password from an OS keystore instead of `.env` (DB_PASSWORD_SOURCE).

Two promises are tested here. Nothing changes for an existing installation: without
DB_PASSWORD_SOURCE the password is DB_PASSWORD, with the same error message when it is
missing. And with a keystore configured the password never has to be in `.env` - each store
is read, a half-finished move (password in both places) is refused, and no error message or
repr ever carries the password itself.

Only fake passwords appear in this file.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

from qlar_data_gateway import cli, secret_store, wizard
from qlar_data_gateway.config import ConfigError, load_settings
from qlar_data_gateway.executor import ExecutionResult

ENDPOINT = "https://qlar.example.com/api/data-gateway"
FAKE_PASSWORD = "fake-pass word#1 "  # trailing space on purpose: it is part of the password

MANAGED_KEYS = (
    "QLAR_BASE_URL",
    "QLAR_ENROLLMENT_CODE",
    "DB_PROVIDER",
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_PASSWORD_SOURCE",
    "DB_PASSWORD_FILE",
    "DB_PASSWORD_KEYRING_SERVICE",
    "DB_PASSWORD_KEYRING_ENTRY",
    "DB_PASSWORD_DPAPI_FILE",
    "DB_PASSWORD_DPAPI_SCOPE",
    "DB_PASSWORD_CREDENTIAL",
    "DB_PASSWORD_CREDENTIAL_FILE",
    "CREDENTIALS_DIRECTORY",
    "AUDIT_LOG_FILE",
)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    """Settings come from the environment, and load_dotenv writes os.environ directly.

    So the whole environment is restored afterwards, not just the keys monkeypatch touched:
    a DB_PASSWORD_SOURCE left behind would change every later test that loads settings.
    """
    before = dict(os.environ)
    for key in MANAGED_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield
    os.environ.clear()
    os.environ.update(before)


@pytest.fixture
def database_env(monkeypatch):
    monkeypatch.setenv("QLAR_BASE_URL", ENDPOINT)
    monkeypatch.setenv("DB_PROVIDER", "postgresql")
    monkeypatch.setenv("DB_HOST", "db.internal")
    monkeypatch.setenv("DB_NAME", "warehouse")
    monkeypatch.setenv("DB_USER", "qlar_readonly")


class FakeKeyring:
    """Stands in for the `keyring` package: a dict keyed by (service, entry)."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, entry: str) -> str | None:
        return self.values.get((service, entry))

    def set_password(self, service: str, entry: str, password: str) -> None:
        self.values[(service, entry)] = password


@pytest.fixture
def fake_keyring(monkeypatch):
    fake = FakeKeyring()
    module = types.ModuleType("keyring")
    module.get_password = fake.get_password
    module.set_password = fake.set_password
    monkeypatch.setitem(sys.modules, "keyring", module)
    return fake


def env_values(env_file: Path) -> dict[str, str]:
    from qlar_data_gateway.config import unquote_env_value

    values = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            values[key.strip()] = unquote_env_value(value.strip())
    return values


class TestDefaultIsUnchanged:
    def test_without_a_source_the_password_is_db_password(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD", FAKE_PASSWORD)

        settings = load_settings(None)

        assert settings.database.password == FAKE_PASSWORD

    def test_explicit_env_source_is_the_same(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "ENV")
        monkeypatch.setenv("DB_PASSWORD", FAKE_PASSWORD)

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_missing_password_keeps_the_old_message(self, database_env):
        with pytest.raises(ConfigError, match=r"missing required database settings: DB_PASSWORD$"):
            load_settings(None)

    def test_an_unknown_source_is_refused_by_name(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "vault")

        with pytest.raises(ConfigError, match="DB_PASSWORD_SOURCE must be one of"):
            load_settings(None)

    def test_the_password_is_not_in_repr(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD", FAKE_PASSWORD)

        settings = load_settings(None)

        assert FAKE_PASSWORD.strip() not in repr(settings)
        assert FAKE_PASSWORD.strip() not in repr(settings.database)


class TestHalfFinishedMove:
    def test_password_in_env_and_keystore_is_refused_without_the_value(
        self, database_env, monkeypatch, fake_keyring
    ):
        fake_keyring.values[("qlar-data-gateway", "db_password")] = FAKE_PASSWORD
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "keyring")
        monkeypatch.setenv("DB_PASSWORD", "fake-leftover")

        with pytest.raises(ConfigError) as caught:
            load_settings(None)

        assert "store-password --from-env" in str(caught.value)
        assert "fake-leftover" not in str(caught.value)

    def test_other_settings_are_reported_before_the_keystore(self, monkeypatch):
        monkeypatch.setenv("QLAR_BASE_URL", ENDPOINT)
        monkeypatch.setenv("DB_PROVIDER", "postgresql")
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "file")

        with pytest.raises(
            ConfigError, match="missing required database settings: DB_HOST, DB_NAME, DB_USER$"
        ):
            load_settings(None)


class TestFileSource:
    def test_reads_the_file_and_drops_only_the_line_ending(self, database_env, monkeypatch, tmp_path):
        secret_file = tmp_path / "db_password"
        secret_file.write_bytes((FAKE_PASSWORD + "\r\n").encode())
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "file")
        monkeypatch.setenv("DB_PASSWORD_FILE", str(secret_file))

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_needs_the_path(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "file")

        with pytest.raises(ConfigError, match="needs DB_PASSWORD_FILE"):
            load_settings(None)

    def test_a_missing_file_is_named(self, database_env, monkeypatch, tmp_path):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "file")
        monkeypatch.setenv("DB_PASSWORD_FILE", str(tmp_path / "absent"))

        with pytest.raises(ConfigError, match="is not a file"):
            load_settings(None)

    def test_an_empty_file_is_refused(self, database_env, monkeypatch, tmp_path):
        secret_file = tmp_path / "db_password"
        secret_file.write_text("\n", encoding="utf-8")
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "file")
        monkeypatch.setenv("DB_PASSWORD_FILE", str(secret_file))

        with pytest.raises(ConfigError, match="is empty"):
            load_settings(None)


class TestSystemdCredentials:
    def test_reads_the_credential_systemd_decrypted(self, database_env, monkeypatch, tmp_path):
        (tmp_path / "db_password").write_text(FAKE_PASSWORD + "\n", encoding="utf-8")
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "systemd-creds")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_a_custom_credential_name(self, database_env, monkeypatch, tmp_path):
        (tmp_path / "warehouse_pw").write_text(FAKE_PASSWORD, encoding="utf-8")
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "systemd-creds")
        monkeypatch.setenv("DB_PASSWORD_CREDENTIAL", "warehouse_pw")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_outside_a_unit_the_error_points_at_the_unit_setting(self, database_env, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "systemd-creds")

        with pytest.raises(ConfigError, match="LoadCredentialEncrypted=db_password"):
            load_settings(None)

    def test_a_missing_credential_is_named(self, database_env, monkeypatch, tmp_path):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "systemd-creds")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

        with pytest.raises(ConfigError, match="'db_password' is not in"):
            load_settings(None)

    def test_store_passes_the_password_on_stdin_not_the_command_line(self, monkeypatch, tmp_path):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            return types.SimpleNamespace(returncode=0, stderr=b"")

        monkeypatch.setattr(secret_store.shutil, "which", lambda _name: "/usr/bin/systemd-creds")
        monkeypatch.setattr(secret_store.subprocess, "run", fake_run)
        target = tmp_path / "credstore" / "db_password"

        where = secret_store.store_db_password(
            "systemd-creds", FAKE_PASSWORD, {"DB_PASSWORD_CREDENTIAL_FILE": str(target)}
        )

        args, kwargs = calls[0]
        assert args == ["/usr/bin/systemd-creds", "encrypt", "--name=db_password", "-", str(target)]
        assert kwargs["input"] == FAKE_PASSWORD.encode()
        assert all(FAKE_PASSWORD not in arg for arg in args)
        assert str(target) in where and FAKE_PASSWORD not in where

    def test_store_reports_a_failure_without_the_password(self, monkeypatch, tmp_path):
        monkeypatch.setattr(secret_store.shutil, "which", lambda _name: "/usr/bin/systemd-creds")
        monkeypatch.setattr(
            secret_store.subprocess,
            "run",
            lambda *_a, **_k: types.SimpleNamespace(returncode=1, stderr=b"Permission denied\n"),
        )

        with pytest.raises(ConfigError, match="Permission denied") as caught:
            secret_store.store_db_password(
                "systemd-creds", FAKE_PASSWORD, {"DB_PASSWORD_CREDENTIAL_FILE": str(tmp_path / "c")}
            )
        assert FAKE_PASSWORD not in str(caught.value)

    def test_store_without_systemd_creds_says_so(self, monkeypatch, tmp_path):
        monkeypatch.setattr(secret_store.shutil, "which", lambda _name: None)

        with pytest.raises(ConfigError, match="systemd-creds was not found"):
            secret_store.store_db_password("systemd-creds", FAKE_PASSWORD, {})


class TestKeyring:
    def test_reads_the_default_entry(self, database_env, monkeypatch, fake_keyring):
        fake_keyring.values[("qlar-data-gateway", "db_password")] = FAKE_PASSWORD
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "keyring")

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_service_and_entry_are_configurable(self, database_env, monkeypatch, fake_keyring):
        fake_keyring.values[("acme-gw", "warehouse")] = FAKE_PASSWORD
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "keyring")
        monkeypatch.setenv("DB_PASSWORD_KEYRING_SERVICE", "acme-gw")
        monkeypatch.setenv("DB_PASSWORD_KEYRING_ENTRY", "warehouse")

        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_a_missing_entry_says_how_to_store_it(self, database_env, monkeypatch, fake_keyring):
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "keyring")

        with pytest.raises(ConfigError, match="store-password --source keyring"):
            load_settings(None)

    def test_without_the_package_the_extra_is_named(self, database_env, monkeypatch):
        monkeypatch.setitem(sys.modules, "keyring", None)  # makes `import keyring` fail
        monkeypatch.setenv("DB_PASSWORD_SOURCE", "keyring")

        with pytest.raises(ConfigError, match=r"qlar-data-gateway\[keystore\]"):
            load_settings(None)

    def test_store_writes_the_entry(self, fake_keyring):
        where = secret_store.store_db_password("keyring", FAKE_PASSWORD, {})

        assert fake_keyring.values[("qlar-data-gateway", "db_password")] == FAKE_PASSWORD
        assert FAKE_PASSWORD not in where

    def test_store_refuses_an_empty_password(self, fake_keyring):
        with pytest.raises(ConfigError, match="empty"):
            secret_store.store_db_password("keyring", "", {})

    def test_file_is_not_a_store_target(self):
        with pytest.raises(ConfigError, match="store-password can write to"):
            secret_store.store_db_password("file", FAKE_PASSWORD, {})


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows only")
class TestDpapiOnWindows:
    def test_round_trip_through_a_sealed_file(self, database_env, monkeypatch, tmp_path):
        sealed = tmp_path / "db-password.dpapi"
        env = {"DB_PASSWORD_DPAPI_FILE": str(sealed)}

        secret_store.store_db_password("dpapi", FAKE_PASSWORD, env)

        content = sealed.read_text(encoding="utf-8")
        assert content.startswith(secret_store.DPAPI_HEADER)
        assert FAKE_PASSWORD.strip() not in content

        monkeypatch.setenv("DB_PASSWORD_SOURCE", "dpapi")
        monkeypatch.setenv("DB_PASSWORD_DPAPI_FILE", str(sealed))
        assert load_settings(None).database.password == FAKE_PASSWORD

    def test_machine_scope_round_trips_too(self, tmp_path):
        env = {"DB_PASSWORD_DPAPI_FILE": str(tmp_path / "pw.dpapi"), "DB_PASSWORD_DPAPI_SCOPE": "machine"}

        secret_store.store_db_password("dpapi", FAKE_PASSWORD, env)

        assert secret_store.resolve_db_password({**env, "DB_PASSWORD_SOURCE": "dpapi"}) == FAKE_PASSWORD

    def test_a_blob_sealed_without_our_entropy_does_not_open(self, tmp_path):
        import base64
        import ctypes
        from ctypes import wintypes

        class DataBlob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        raw = ctypes.create_string_buffer(b"fake-other-app", 14)
        data_in = DataBlob(14, ctypes.cast(raw, ctypes.POINTER(ctypes.c_char)))
        data_out = DataBlob()
        assert ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(data_in), None, None, None, None, 1, ctypes.byref(data_out)
        )
        blob = ctypes.string_at(data_out.pbData, data_out.cbData)
        ctypes.windll.kernel32.LocalFree(data_out.pbData)

        sealed = tmp_path / "pw.dpapi"
        sealed.write_text(
            f"{secret_store.DPAPI_HEADER}\n{base64.b64encode(blob).decode()}\n", encoding="utf-8"
        )

        with pytest.raises(ConfigError, match="could not open the DPAPI password file"):
            secret_store.resolve_db_password(
                {"DB_PASSWORD_SOURCE": "dpapi", "DB_PASSWORD_DPAPI_FILE": str(sealed)}
            )

    def test_a_foreign_file_is_named(self, tmp_path):
        sealed = tmp_path / "pw.dpapi"
        sealed.write_text("not ours\n", encoding="utf-8")

        with pytest.raises(ConfigError, match="not a password file"):
            secret_store.resolve_db_password(
                {"DB_PASSWORD_SOURCE": "dpapi", "DB_PASSWORD_DPAPI_FILE": str(sealed)}
            )


class TestDpapiAnywhere:
    def test_a_missing_file_says_how_to_create_it(self, tmp_path):
        with pytest.raises(ConfigError, match="store-password --source dpapi"):
            secret_store.resolve_db_password(
                {"DB_PASSWORD_SOURCE": "dpapi", "DB_PASSWORD_DPAPI_FILE": str(tmp_path / "absent")}
            )

    def test_off_windows_it_is_refused_by_name(self, monkeypatch):
        monkeypatch.setattr(secret_store.sys, "platform", "linux")

        with pytest.raises(ConfigError, match="only available on Windows"):
            secret_store.dpapi_protect(b"fake")

    def test_an_unknown_scope_is_refused(self):
        with pytest.raises(ConfigError, match="DB_PASSWORD_DPAPI_SCOPE"):
            secret_store.store_db_password("dpapi", FAKE_PASSWORD, {"DB_PASSWORD_DPAPI_SCOPE": "domain"})


class TestRemovePasswordFromEnv:
    def test_only_the_password_line_goes(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# DB_PASSWORD=documented in a comment\nDB_HOST=db.internal\n"
            "DB_PASSWORD=fake\n'DB_PASSWORD=fake2'\nDB_PASSWORD_SOURCE=keyring\n",
            encoding="utf-8",
        )

        assert secret_store.remove_password_from_env(env_file) is True

        assert env_file.read_text(encoding="utf-8") == (
            "# DB_PASSWORD=documented in a comment\nDB_HOST=db.internal\nDB_PASSWORD_SOURCE=keyring\n"
        )

    def test_nothing_to_remove(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DB_HOST=db.internal\n", encoding="utf-8")

        assert secret_store.remove_password_from_env(env_file) is False
        assert secret_store.remove_password_from_env(tmp_path / "absent") is False


class TestStorePasswordCommand:
    def test_from_env_moves_the_password_into_the_keyring(
        self, tmp_path, fake_keyring, database_env, monkeypatch
    ):
        env_file = tmp_path / ".env"
        env_file.write_text(f'DB_HOST=db.internal\nDB_PASSWORD="{FAKE_PASSWORD}"\n', encoding="utf-8")
        monkeypatch.delenv("DB_HOST")

        code = cli.main(["--env-file", str(env_file), "store-password", "--source", "keyring", "--from-env"])

        assert code == 0
        assert fake_keyring.values[("qlar-data-gateway", "db_password")] == FAKE_PASSWORD
        saved = env_values(env_file)
        assert "DB_PASSWORD" not in saved
        assert saved["DB_PASSWORD_SOURCE"] == "keyring"
        assert FAKE_PASSWORD.strip() not in env_file.read_text(encoding="utf-8")

        # And the next start finds it there.
        assert load_settings(env_file).database.password == FAKE_PASSWORD

    def test_from_env_without_a_password_changes_nothing(self, tmp_path, fake_keyring):
        env_file = tmp_path / ".env"
        env_file.write_text("DB_HOST=db.internal\n", encoding="utf-8")

        code = cli.main(["--env-file", str(env_file), "store-password", "--source", "keyring", "--from-env"])

        assert code == 2
        assert fake_keyring.values == {}
        assert "DB_PASSWORD_SOURCE" not in env_values(env_file)

    def test_typed_twice_and_different_stores_nothing(self, tmp_path, fake_keyring, monkeypatch):
        answers = iter(["fake-one", "fake-two"])
        monkeypatch.setattr(cli, "prompt_for_secret", lambda _prompt: next(answers))
        monkeypatch.setattr(cli, "can_prompt", lambda: True)
        env_file = tmp_path / ".env"

        code = cli.main(["--env-file", str(env_file), "store-password", "--source", "keyring"])

        assert code == 1
        assert fake_keyring.values == {}

    def test_typed_twice_and_equal_is_stored(self, tmp_path, fake_keyring, monkeypatch):
        monkeypatch.setattr(cli, "prompt_for_secret", lambda _prompt: FAKE_PASSWORD)
        monkeypatch.setattr(cli, "can_prompt", lambda: True)
        env_file = tmp_path / ".env"

        code = cli.main(["--env-file", str(env_file), "store-password", "--source", "keyring"])

        assert code == 0
        assert fake_keyring.values[("qlar-data-gateway", "db_password")] == FAKE_PASSWORD
        assert env_values(env_file)["DB_PASSWORD_SOURCE"] == "keyring"

    def test_needs_a_store(self, tmp_path, capsys):
        code = cli.main(["--env-file", str(tmp_path / ".env"), "store-password", "--from-env"])

        assert code == 2
        assert "--source" in capsys.readouterr().err


class TestSetupPromptsWithAKeystore:
    def test_the_password_goes_to_the_keyring_and_not_into_env(self, tmp_path, monkeypatch, fake_keyring):
        env_file = tmp_path / ".env"
        env_file.write_text("DB_PASSWORD_SOURCE=keyring\nDB_PASSWORD=fake-old-plaintext\n", encoding="utf-8")
        answers = iter(["", "db.internal", "", "warehouse", "qlar_readonly", FAKE_PASSWORD, ENDPOINT])
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
        monkeypatch.setattr(wizard, "prompt_for_secret", lambda _prompt="": next(answers))
        monkeypatch.setattr(wizard, "can_prompt", lambda: True)
        monkeypatch.setattr(
            wizard,
            "test_connection",
            lambda _s: ExecutionResult(status="ok", rows=[["PostgreSQL 16"]], row_count=1, duration_ms=1),
        )
        monkeypatch.setattr(wizard, "account_can_write", lambda _s: False)

        settings, ok = wizard.run_setup(env_file)

        assert ok is True
        assert settings.database.password == FAKE_PASSWORD
        assert fake_keyring.values[("qlar-data-gateway", "db_password")] == FAKE_PASSWORD
        saved = env_values(env_file)
        assert "DB_PASSWORD" not in saved
        assert saved["DB_PASSWORD_SOURCE"] == "keyring"
        assert "fake-old-plaintext" not in env_file.read_text(encoding="utf-8")
