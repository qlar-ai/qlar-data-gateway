"""Settings and persisted enrolment state.

Two files, with deliberately different lifetimes:

* `.env` — written by the operator, or by the setup prompts on first run (see
  `wizard.py`). Qlar's URL, the one-time enrolment code, and the database credentials.
  **The database credentials live here and only here**; they are never sent to Qlar.
* `gateway-state.json` — written by the gateway at enrolment. The gateway id Qlar issued
  and Qlar's public key, pinned so later jobs can be verified.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED_PROVIDERS = ("postgresql", "mysql", "sqlserver", "oracle", "parquet")

# Providers that read files on this machine rather than talking to a database server. They
# have no host, user or password - only a folder - and run the query engine inside this
# process, which is why their resource limits are settings of the gateway itself.
FILE_PROVIDERS = ("parquet",)

DEFAULT_STATEMENT_TIMEOUT_SECONDS = 30
DEFAULT_POLL_TIMEOUT_SECONDS = 25
DEFAULT_MAX_RESULT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_CONCURRENT_QUERIES = 5
# One DuckDB query already uses every thread it is given, so a second one beside it only
# halves the speed of both and doubles the memory. Queue them instead.
DEFAULT_MAX_CONCURRENT_FILE_QUERIES = 1
DEFAULT_PARQUET_MEMORY_LIMIT = "50%"
DEFAULT_PARQUET_MAX_TEMP_SIZE = "20GB"


class ConfigError(Exception):
    """The gateway cannot start with the configuration it was given."""


def load_dotenv(path: Path) -> None:
    """Loads `KEY=value` lines into the environment without overwriting real env vars.

    Hand-rolled rather than pulling in python-dotenv: the format we need is three lines of
    parsing, and every dependency in this process is one more thing a customer's security
    review has to cover. Real environment variables win, so a container can override the
    file without editing it.
    """
    if not path.exists():
        return

    for raw_line in read_env_text(path).splitlines():
        line = unwrap_quoted_line(raw_line.strip())
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = unquote_env_value(value.strip())
        if key and key not in os.environ:
            os.environ[key] = value


def read_env_text(path: Path) -> str:
    """Reads an env file, naming the encoding problems Windows creates rather than crashing.

    Two of them, both from an operator following instructions on the wrong shell:

    * **UTF-16.** PowerShell 5.1's `>>` writes it. Decoded as UTF-8 the file is either a
      `UnicodeDecodeError` traceback or, worse, silence - so it is detected and explained.
    * **A UTF-8 BOM.** Several Windows editors add one, and it would otherwise become part
      of the first key, which then matches nothing and is invisible on screen.
    """
    raw = path.read_bytes()

    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or raw[1:2] == b"\x00":
        raise ConfigError(
            f"{path} is UTF-16 encoded, which usually means it was written by PowerShell's "
            "`>>` operator. Save it as UTF-8, or delete it and let the setup prompts write it."
        )

    try:
        # utf-8-sig drops a BOM when there is one and behaves as plain UTF-8 when there is not.
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ConfigError(
            f"{path} is not valid UTF-8 ({error}). Save it as UTF-8, or delete it and let the "
            "setup prompts write it."
        ) from error


def unwrap_quoted_line(line: str) -> str:
    """Unwraps a whole `'KEY=value'` line, which is what cmd.exe writes.

    `echo 'KEY=value' >> .env` is correct in a POSIX shell and a trap in cmd, which has no
    single-quote quoting and writes the quotes literally. The result is a key named `'KEY`
    that matches nothing, while the line on screen looks exactly right — the operator sees
    their setting in the file and the gateway says it is unset.

    Unwrapping costs nothing: a value that is itself quoted, `KEY='value'`, does not start
    with a quote, so it is left to `unquote_env_value` as before.
    """
    if len(line) >= 2 and line[0] == line[-1] and line[0] in "\"'" and "=" in line[1:-1]:
        return line[1:-1].strip()
    return line


def unquote_env_value(value: str) -> str:
    """Removes one matching pair of surrounding quotes, and only one.

    Quoting is how a password with a leading space, a trailing space or a `#` survives the
    round trip through this file; stripping every quote character instead would corrupt a
    password that legitimately ends in one.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def quote_env_value(value: str) -> str:
    """Formats a value for a `KEY=value` line, quoting it when it would not survive plain.

    The counterpart of `unquote_env_value`. Anything that the loader's `strip()` would eat,
    that a human would read as the start of a comment, or that a shell would split on gets
    wrapped in double quotes. A space inside a password survives either way here, but the
    line is regularly copied into a terminal, where it would not.
    """
    if value == "":
        return ""
    needs_quotes = (
        any(character.isspace() for character in value)
        or "#" in value
        or (value[0] in "\"'" and value[-1] == value[0])
    )
    return f'"{value}"' if needs_quotes else value


def write_env_values(path: Path, values: dict[str, str]) -> Path | None:
    """Writes `KEY=value` settings into an env file, updating keys where they already are.

    Rewriting the file rather than appending keeps it readable after the tenth `--init`:
    a key that is already there is replaced in place, comments and hand-added settings are
    left exactly as they were, and only genuinely new keys are appended.

    The file holds a database password, so it is created with mode 0600 already set — the
    same reasoning as the private key in `crypto.py`. It is truncated and rewritten in
    place rather than written beside and renamed: a `.env` is routinely bind-mounted into
    a container by path, and a rename would leave the container holding the old inode.

    Returns the path an unreadable existing file was moved to, or None. A file this cannot
    parse is never silently overwritten — whatever is in it was put there by someone.
    """
    backup: Path | None = None
    lines = _new_env_file_header()

    if path.exists():
        try:
            lines = read_env_text(path).splitlines()
        except ConfigError:
            backup = path.with_suffix(path.suffix + ".bak")
            path.replace(backup)

    remaining = dict(values)
    rewritten: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in remaining:
                rewritten.append(f"{key}={quote_env_value(remaining.pop(key))}")
                continue
        rewritten.append(line)

    if remaining:
        if rewritten and rewritten[-1].strip():
            rewritten.append("")
        rewritten.extend(f"{key}={quote_env_value(value)}" for key, value in remaining.items())

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(rewritten) + "\n")

    # os.open only applies the mode when it creates the file; an existing .env written by
    # hand may be world-readable, and it now contains a password either way.
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows, or a filesystem without modes
        pass

    return backup


def _new_env_file_header() -> list[str]:
    """The comment block a freshly generated `.env` starts with.

    Deliberately short. The settings the prompts ask about are appended below it, and the
    handful worth knowing exist are listed commented-out so that the file answers "what
    else can I set here?" without anyone having to find `.env.example` again.
    """
    return [
        "# Qlar Data Gateway - configuration",
        "#",
        "# Generated by `qlar-gateway --init`. Real environment variables take precedence",
        "# over this file, so a container or systemd unit can override any line below.",
        "#",
        "# This file contains your database password: keep it mode 0600 and out of version",
        "# control. Re-run `qlar-gateway run --init` to change these answers.",
        "#",
        "# Other settings, with their defaults - uncomment to change one:",
        "#QLAR_GATEWAY_NAME=            # label shown in the CMS; defaults to the hostname",
        "#QLAR_ENROLLMENT_CODE=         # one-time code from the CMS, only needed for `enroll`",
        "#DB_OPT_SSLMODE=verify-full    # any DB_OPT_* is passed to the driver lower-cased",
        "#TABLE_ALLOWLIST=              # when set, ONLY these tables can be read",
        "#DB_STATEMENT_TIMEOUT_SECONDS=30",
        "#MAX_RESULT_BYTES=10485760",
        "#MAX_CONCURRENT_QUERIES=5      # 1 when DB_PROVIDER=parquet",
        "#PARQUET_TABLES_FILE=          # parquet: optional table names and descriptions",
        "#PARQUET_MEMORY_LIMIT=50%      # parquet: DuckDB memory ceiling (size or % of RAM)",
        "#PARQUET_THREADS=              # parquet: defaults to every core",
        "#PARQUET_TEMP_DIR=             # parquet: spill folder, defaults beside the state file",
        "#PARQUET_MAX_TEMP_SIZE=20GB",
        "#AUDIT_LOG_FILE=./audit/queries.jsonl",
        "#GATEWAY_KEY_FILE=./gateway-key.pem",
        "#GATEWAY_STATE_FILE=./gateway-state.json",
        "#POLL_TIMEOUT_SECONDS=25",
        "#LOG_LEVEL=INFO",
        "",
    ]


@dataclass(frozen=True)
class DatabaseSettings:
    provider: str
    host: str
    port: int | None
    database: str
    user: str
    password: str
    # Provider-specific connect options, e.g. sslmode for PostgreSQL or an Oracle service
    # name. Kept as a plain mapping so a customer can pass something we did not anticipate
    # without waiting for a release.
    options: dict[str, str] = field(default_factory=dict)

    statement_timeout_seconds: int = DEFAULT_STATEMENT_TIMEOUT_SECONDS
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    # Optional hardening: when set, a query may only touch these tables, whatever Qlar
    # asks for. This list lives on-premise precisely so that a compromise of Qlar cannot
    # widen it. Names are matched case-insensitively, schema-qualified where the database
    # has schemas.
    table_allowlist: frozenset[str] = frozenset()

    # Only for `parquet`: where the files are and how much of this machine DuckDB may use.
    parquet: ParquetSettings | None = None

    @property
    def is_file_source(self) -> bool:
        return self.provider in FILE_PROVIDERS

    def describe(self) -> str:
        """Where this gateway reads from, for logs and setup output. Never the password."""
        if self.parquet is not None:
            return f"parquet://{self.parquet.root}"
        port = f":{self.port}" if self.port else ""
        return f"{self.provider}://{self.user}@{self.host}{port}/{self.database}"


@dataclass(frozen=True)
class ParquetSettings:
    """A folder of Parquet files, queried in-process with DuckDB.

    Attributes:
        root: the folder. Each sub-folder (partitioned or not) and each `*.parquet` file
            directly inside it becomes one table. Nothing outside it can be read.
        tables_file: optional JSON or TOML file that renames, adds, excludes and describes
            tables and columns. A relative path resolves against `root`.
        memory_limit: DuckDB `memory_limit`, a size (`8GB`) or a share of RAM (`50%`).
        threads: DuckDB `threads`; None keeps DuckDB's default of every core.
        temp_dir: where DuckDB spills a query that does not fit in `memory_limit`.
        max_temp_size: ceiling on that spill folder.
    """

    root: str
    tables_file: str = ""
    memory_limit: str = DEFAULT_PARQUET_MEMORY_LIMIT
    threads: int | None = None
    temp_dir: str = ""
    max_temp_size: str = DEFAULT_PARQUET_MAX_TEMP_SIZE


@dataclass(frozen=True)
class Settings:
    base_url: str
    gateway_name: str
    enrollment_code: str | None
    key_file: Path
    state_file: Path
    audit_log_file: Path | None
    poll_timeout_seconds: int
    max_concurrent_queries: int
    verify_tls: bool
    database: DatabaseSettings


@dataclass
class EnrollmentState:
    """What the gateway learned at enrolment, persisted across restarts."""

    gateway_id: str
    qlar_public_key_pem: str
    enrolled_at: str
    base_url: str

    @classmethod
    def load(cls, path: Path) -> EnrollmentState | None:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            gateway_id=data["gatewayId"],
            qlar_public_key_pem=data["qlarPublicKeyPem"],
            enrolled_at=data["enrolledAt"],
            base_url=data["baseUrl"],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "gatewayId": self.gateway_id,
                    "qlarPublicKeyPem": self.qlar_public_key_pem,
                    "enrolledAt": self.enrolled_at,
                    "baseUrl": self.base_url,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from error


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _collect_db_options() -> dict[str, str]:
    """Every `DB_OPT_<NAME>` variable becomes a lower-cased driver option."""
    prefix = "DB_OPT_"
    return {
        key[len(prefix) :].lower(): value
        for key, value in os.environ.items()
        if key.startswith(prefix) and value != ""
    }


def load_settings(env_file: Path | None = None) -> Settings:
    """Builds the settings, raising ConfigError with an actionable message on any gap."""
    if env_file is not None:
        load_dotenv(env_file)

    base_url = os.environ.get("QLAR_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        raise ConfigError(
            "QLAR_BASE_URL is required. The Qlar CMS gateway panel shows it; it ends in "
            "/api/data-gateway"
        )
    if not base_url.startswith("https://") and "localhost" not in base_url and "127.0.0.1" not in base_url:
        raise ConfigError("QLAR_BASE_URL must use https:// outside local testing")

    provider = os.environ.get("DB_PROVIDER", "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise ConfigError(
            f"DB_PROVIDER must be one of {', '.join(SUPPORTED_PROVIDERS)}, got {provider or '(unset)'}"
        )

    allowlist = {
        name.strip().lower()
        for name in os.environ.get("TABLE_ALLOWLIST", "").split(",")
        if name.strip()
    }
    state_file = Path(os.environ.get("GATEWAY_STATE_FILE", "./gateway-state.json")).expanduser()
    statement_timeout = _env_int("DB_STATEMENT_TIMEOUT_SECONDS", DEFAULT_STATEMENT_TIMEOUT_SECONDS)

    if provider in FILE_PROVIDERS:
        database = DatabaseSettings(
            provider=provider,
            host="",
            port=None,
            database="",
            user="",
            password="",
            statement_timeout_seconds=statement_timeout,
            max_result_bytes=_env_int("MAX_RESULT_BYTES", DEFAULT_MAX_RESULT_BYTES),
            table_allowlist=frozenset(allowlist),
            parquet=_load_parquet_settings(state_file),
        )
        default_concurrency = DEFAULT_MAX_CONCURRENT_FILE_QUERIES
    else:
        required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ConfigError(f"missing required database settings: {', '.join(missing)}")

        port_raw = os.environ.get("DB_PORT", "").strip()
        database = DatabaseSettings(
            provider=provider,
            host=os.environ["DB_HOST"].strip(),
            port=int(port_raw) if port_raw else None,
            database=os.environ["DB_NAME"].strip(),
            user=os.environ["DB_USER"].strip(),
            password=os.environ["DB_PASSWORD"],
            options=_collect_db_options(),
            statement_timeout_seconds=statement_timeout,
            max_result_bytes=_env_int("MAX_RESULT_BYTES", DEFAULT_MAX_RESULT_BYTES),
            table_allowlist=frozenset(allowlist),
        )
        default_concurrency = DEFAULT_MAX_CONCURRENT_QUERIES

    audit_raw = os.environ.get("AUDIT_LOG_FILE", "./audit/queries.jsonl").strip()

    return Settings(
        base_url=base_url,
        gateway_name=os.environ.get("QLAR_GATEWAY_NAME", "").strip() or _default_gateway_name(),
        enrollment_code=(os.environ.get("QLAR_ENROLLMENT_CODE") or "").strip() or None,
        key_file=Path(os.environ.get("GATEWAY_KEY_FILE", "./gateway-key.pem")).expanduser(),
        state_file=state_file,
        audit_log_file=Path(audit_raw).expanduser() if audit_raw else None,
        poll_timeout_seconds=_env_int("POLL_TIMEOUT_SECONDS", DEFAULT_POLL_TIMEOUT_SECONDS),
        max_concurrent_queries=_env_int("MAX_CONCURRENT_QUERIES", default_concurrency),
        # Only ever disabled for testing against a local Qlar with a self-signed cert;
        # the flag is named so that it reads as a mistake in a production .env.
        verify_tls=_env_bool("QLAR_INSECURE_SKIP_TLS_VERIFY", False) is False,
        database=database,
    )


def _load_parquet_settings(state_file: Path) -> ParquetSettings:
    """Reads the `PARQUET_*` settings, checking the folder exists before anything polls."""
    root_raw = os.environ.get("PARQUET_ROOT", "").strip()
    if not root_raw:
        raise ConfigError("PARQUET_ROOT is required for DB_PROVIDER=parquet: the folder holding the files")

    root = Path(root_raw).expanduser().resolve()
    if not root.is_dir():
        raise ConfigError(f"PARQUET_ROOT {root} is not a folder this process can see")

    threads: int | None = None
    if os.environ.get("PARQUET_THREADS", "").strip():
        threads = _env_int("PARQUET_THREADS", 0)
        if threads < 1:
            raise ConfigError("PARQUET_THREADS must be 1 or more")

    temp_raw = os.environ.get("PARQUET_TEMP_DIR", "").strip()
    # Beside the state file by default: that is the one folder the operator has already
    # given the gateway to write in (the /state volume in the container).
    temp_dir = Path(temp_raw).expanduser() if temp_raw else state_file.parent / "duckdb-tmp"

    return ParquetSettings(
        root=str(root),
        tables_file=os.environ.get("PARQUET_TABLES_FILE", "").strip(),
        memory_limit=os.environ.get("PARQUET_MEMORY_LIMIT", "").strip() or DEFAULT_PARQUET_MEMORY_LIMIT,
        threads=threads,
        temp_dir=str(temp_dir.resolve()),
        max_temp_size=os.environ.get("PARQUET_MAX_TEMP_SIZE", "").strip() or DEFAULT_PARQUET_MAX_TEMP_SIZE,
    )


def _default_gateway_name() -> str:
    import socket

    return f"{socket.gethostname()} gateway"
