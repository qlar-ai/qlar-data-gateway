"""First-run setup: ask for the database details, write them to `.env`, prove they work.

Installing the gateway and starting it should be the whole job. Copying `.env.example`,
remembering which variable names the loader expects, and discovering a typo hours later
when the first query fails is work that a handful of prompts can do instead.

So a start with no usable configuration asks, writes the answers to `.env`, and runs one
query against the database before going any further. The answers are written to the file
precisely so that this happens exactly once: the next start — a restart, a systemd unit, a
replaced container — reads the file and never asks again. `--init` asks anyway, for the
day the password rotates or the database moves.

None of this is mandatory. A `.env` written by hand, or environment variables set by a
container, still take precedence and the prompts never appear; and without a terminal to
ask on, the old configuration error is printed exactly as before. The prompts are a
convenience for a human at a console, never a new requirement for automation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import console
from .config import (
    FILE_PROVIDERS,
    SUPPORTED_PROVIDERS,
    ConfigError,
    Settings,
    load_dotenv,
    load_settings,
    read_env_text,
    unquote_env_value,
    unwrap_quoted_line,
    write_env_values,
)
from .executor import account_can_write, test_connection
from .masked_input import prompt_for_secret
from .providers import default_port

# No default. The endpoint differs per Qlar deployment, the CMS gateway panel prints the
# right one, and a plausible-looking guess is worse than a question: it fails at enrolment
# with a 404 that reads like a rejected code.
BASE_URL_HINT = "ends in /api/data-gateway - the CMS gateway panel shows it"

# Names people actually type, mapped to the four `DB_PROVIDER` values.
PROVIDER_ALIASES = {
    "postgres": "postgresql",
    "postgre": "postgresql",
    "pg": "postgresql",
    "psql": "postgresql",
    "mariadb": "mysql",
    "mssql": "sqlserver",
    "sqlsrv": "sqlserver",
    "sql server": "sqlserver",
    "ora": "oracle",
    "duckdb": "parquet",
    "files": "parquet",
}


class SetupAborted(Exception):
    """The operator cancelled the prompts, or there was no terminal to ask on."""


def can_prompt() -> bool:
    """True when there is a human at a console to answer.

    A container started without a TTY, a systemd unit and a cron job all answer False here
    and get the configuration error they have always got. Prompting into a log file that
    nobody is reading would turn a clear failure into a process that appears to hang.
    """
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):  # pragma: no cover - detached stdin
        return False


def run_setup(env_file: Path, *, ask_endpoint: bool = True, reason: str = "") -> tuple[Settings, bool]:
    """Asks for the database details, saves them, and tests them.

    Returns the settings and whether the test query succeeded. A failed test is not fatal:
    the operator is told, offered another go, and — if they decline — left with a saved
    `.env` they can fix by hand or with `--init`. Refusing to continue would be worse; a
    database that is merely down at this moment is a normal thing for a service to survive.
    """
    # Whatever is already configured becomes the default answer, so re-running `--init`
    # to change one field is a row of Enter presses and one new value.
    try:
        load_dotenv(env_file)
    except ConfigError as error:
        # An unreadable file has nothing to offer as defaults, but it is not a reason to
        # refuse to set the gateway up - that is exactly what the operator is here for.
        print(f"Ignoring the existing file: {error}", file=sys.stderr)

    _banner(env_file, reason)

    while True:
        answers = _collect_answers(ask_endpoint=ask_endpoint)
        backup = write_env_values(env_file, answers)
        if backup is not None:
            print(f"\nThe previous {env_file} could not be read; it is kept as {backup}.")

        # The file is for the *next* start; this process is already past the point where
        # it read the environment, so the answers go into it directly.
        os.environ.update(answers)

        try:
            # Not `load_settings(env_file)`: the file has just been loaded, and real
            # environment variables win there, which would hide the answers just given.
            settings = load_settings(None)
        except ConfigError as error:
            print(f"That configuration cannot be used: {error}", file=sys.stderr)
            if _ask_yes_no("Enter the details again?", default=True):
                continue
            raise SetupAborted(str(error)) from error

        if check_connection(settings, prominent=True):
            return settings, True

        print()
        if _ask_yes_no("Enter the details again?", default=True):
            continue

        print(
            f"Leaving the details as saved in {env_file}. "
            "Fix them there, or run `qlar-gateway run --init` to be asked again.",
            file=sys.stderr,
        )
        return settings, False


def ask_enrollment_code() -> str:
    """Asks for the one-time code, rather than sending the operator back to edit a file.

    This is the one answer the setup prompts used to leave out, and it is the one most
    likely to be got wrong: it arrives by copy and paste from a web page, into a file, on a
    machine whose shell may not quote the way the instructions assumed. A prompt has no
    shell in it at all.

    Not written to `.env`. The code is single-use and spent the moment enrolment succeeds,
    so keeping it would leave a dead credential on disk and one more thing to explain.
    """
    print()
    print("The one-time enrolment code is shown in the Qlar CMS:")
    print("  your agent > Plugins > SQL Database Reader > Connect via gateway")
    print("It expires 15 minutes after it is generated, and works once.")

    while True:
        answer = _ask("  Enrolment code")
        # Forgiving about how it arrived: pasted with the quotes from a shell snippet, in
        # lower case, or with stray spaces. The alphabet the CMS generates is upper case.
        code = unquote_env_value(answer.strip()).strip().upper()
        if code:
            return code


def check_connection(settings: Settings, *, prominent: bool = False) -> bool:
    """Runs one query against the database and reports what happened, in words.

    Used at every start, not only during setup: the most common support question about any
    on-premise agent is "is it actually talking to my database?", and the honest place to
    answer it is the first line of the log rather than the first failed query an hour later.
    """
    database = settings.database
    if database.is_file_source:
        address = database.describe()
    else:
        port = database.port or default_port(database.provider)
        address = f"{database.provider}://{database.user}@{database.host}:{port}/{database.database}"

    if prominent:
        console.separator("TESTING THE DATABASE CONNECTION")
        print(f"  {address}")
        print()

    # Run first, print second: a failure belongs entirely on stderr, and half a block on
    # each stream interleaves into nonsense the moment anyone redirects one of them.
    result = test_connection(database)

    if result.status != "ok":
        error = result.error or {}
        lines = [str(error.get("messageText"))]
        if error.get("hint"):
            lines.append(f"hint: {error['hint']}")

        if prominent:
            console.badge("FAIL", "bad", str(error.get("category")), *lines, file=sys.stderr)
        else:
            console.field("database", address, file=sys.stderr)
            console.field("connection", f"FAILED ({error.get('category')})", file=sys.stderr)
            for line in lines:
                console.detail(line, file=sys.stderr)
        return False

    version = _one_line(str((result.rows or [[""]])[0][0]))

    if prominent:
        console.badge(" OK ", "ok", f"connected in {result.duration_ms} ms", version)
    else:
        console.field("database", address)
        console.success("connection", f"OK in {result.duration_ms} ms")
        console.field("server", version)

    # Advisory, never fatal. An operator who deliberately granted more is not blocked, but
    # nobody should discover months later that the "read-only" gateway could drop tables.
    # Given its own block: following a success, a warning set in the same shape as the rest
    # reads as more of the success.
    if database.is_file_source:
        if account_can_write(database) is True:
            console.warning(
                "This process can modify the Parquet files",
                "The gateway only ever runs SELECT statements, but a folder the gateway can only",
                "read is the guarantee that does not depend on our code being right.",
                "",
                "Mount it read-only (docker: -v /data/parquet:/data:ro) or remove write access",
                "for the account the gateway runs as.",
            )
        return True

    if account_can_write(database) is True:
        console.warning(
            "This database account appears able to modify data",
            "The gateway only ever issues read-only transactions, but a read-only account",
            "is the guarantee that does not depend on our code being right.",
            "",
            "Create one with SELECT and nothing more, then point DB_USER at it:",
            "  CREATE ROLE qlar_readonly LOGIN PASSWORD '...';",
            "  GRANT SELECT ON ALL TABLES IN SCHEMA public TO qlar_readonly;",
        )
    return True


def _banner(env_file: Path, reason: str = "") -> None:
    """The header, carrying only what the operator cannot already see.

    A fresh install gets none of it: they are standing in the directory, the file does not
    exist, and the reason they are being asked is that nothing is configured yet - three
    facts nobody needs told. The two lines that remain conditional earn their place only
    when they say something surprising: a file that already has settings in it (which is
    what makes "why is it asking me again?" answerable), or an env file somewhere other
    than here.
    """
    console.banner("Setup - a few answers before the gateway can start")

    if env_file.exists():
        console.field("found", _describe_existing(env_file))
    if env_file.resolve() != (Path.cwd() / ".env").resolve():
        console.field("saving to", env_file.resolve())
    if env_file.exists() or env_file.resolve() != (Path.cwd() / ".env").resolve():
        print()

    print("  Enter accepts the value in [brackets];  Press Ctrl-C to cancel.")
    print()


def _describe_existing(env_file: Path) -> str:
    """Says what was read from the file, by key name, before asking for it again.

    Being asked for something that is already written down is infuriating, and the reason
    is never visible: the file is in another directory, or the shell that wrote it used an
    encoding this cannot read, or the line is subtly not a setting. Naming the keys that
    were understood answers all three at a glance — and names only, never values, because
    one of them is a database password.
    """
    if not env_file.exists():
        return "no file there yet, so nothing is filled in for you"

    try:
        recognised = [
            line.partition("=")[0].strip()
            for raw in read_env_text(env_file).splitlines()
            if (line := unwrap_quoted_line(raw.strip()))
            and not line.startswith("#")
            and "=" in line
        ]
    except ConfigError as error:
        return f"unreadable - {error}"

    if not recognised:
        return "a file with no settings in it, so nothing is filled in for you"
    return ", ".join(recognised)


def _collect_answers(*, ask_endpoint: bool = True) -> dict[str, str]:
    """The questions themselves, in the order someone reads them off a connection string.

    `ask_endpoint` is False when the endpoint arrived on the command line: asking for an
    answer that was just supplied is how a tool teaches people to stop reading its prompts.
    """
    total = 7 if ask_endpoint else 6

    console.heading(f"YOUR DATABASE       ({total} answers in all)")
    print("    " + "   ".join(f"{index}) {name}" for index, name in enumerate(SUPPORTED_PROVIDERS, 1)))
    print()

    provider = _ask_provider(_current("DB_PROVIDER").lower() or SUPPORTED_PROVIDERS[0], f"1/{total}")

    if provider in FILE_PROVIDERS:
        return _collect_parquet_answers(provider, ask_endpoint=ask_endpoint)

    # Nobody keeps the five parts of a connection separate in their head; they have a URL
    # from their DBA. Accept it whole and use its parts as the defaults below, still shown
    # one by one so that what was understood is visible before anything is saved.
    host_answer = _ask("Host or URL", _current("DB_HOST") or None, f"2/{total}")
    pasted = _parse_connection_url(host_answer)
    host = pasted.get("host") or host_answer

    port = _ask_port(
        pasted.get("port") or _current("DB_PORT") or str(default_port(provider) or ""), f"3/{total}"
    )
    database = _ask("Database name", pasted.get("database") or _current("DB_NAME") or None, f"4/{total}")
    user = _ask("Username", pasted.get("user") or _current("DB_USER") or None, f"5/{total}")

    url_password = pasted.get("password")
    saved_password = _current("DB_PASSWORD", strip=False)
    keep_label = "from the URL" if url_password else ("unchanged" if saved_password else None)
    password = _ask_secret("Password", keep_label=keep_label, number=f"6/{total}") or (
        url_password or saved_password
    )

    if ask_endpoint:
        # No paragraph explaining what this is: the endpoint reaches almost everyone as
        # `enroll --base-url ...`, straight from the CMS panel, and whoever lands here
        # instead is reading the same panel.
        print()
        console.heading("QLAR")
        base_url = _ask("API endpoint", _current("QLAR_BASE_URL") or None, f"7/{total}").rstrip("/")
    else:
        base_url = _current("QLAR_BASE_URL").rstrip("/")

    return {
        "QLAR_BASE_URL": base_url,
        "DB_PROVIDER": provider,
        "DB_HOST": host,
        "DB_PORT": port,
        "DB_NAME": database,
        "DB_USER": user,
        "DB_PASSWORD": password,
    }


def _collect_parquet_answers(provider: str, *, ask_endpoint: bool) -> dict[str, str]:
    """A folder instead of a server: one question, plus the endpoint."""
    total = 3 if ask_endpoint else 2
    while True:
        root = _ask("Folder with the Parquet files", _current("PARQUET_ROOT") or None, f"2/{total}")
        if Path(root).expanduser().is_dir():
            break
        _complain(f"{root} is not a folder this process can see")

    if ask_endpoint:
        print()
        console.heading("QLAR")
        base_url = _ask("API endpoint", _current("QLAR_BASE_URL") or None, f"3/{total}").rstrip("/")
    else:
        base_url = _current("QLAR_BASE_URL").rstrip("/")

    return {"QLAR_BASE_URL": base_url, "DB_PROVIDER": provider, "PARQUET_ROOT": root}


def _current(name: str, *, strip: bool = True) -> str:
    value = os.environ.get(name, "")
    return value.strip() if strip else value


# The form's columns. Answers typed into a ragged prompt look like a ransom note, and
# the eye cannot check them against each other afterwards; one column for the label and
# one for the default puts every answer the operator typed in the same place.
LABEL_WIDTH = 14
DEFAULT_WIDTH = 16


def _prompt(label: str, default: str | None, number: str = "") -> str:
    """One line of the form: `  3/7 Port          [5432]        : `.

    A default too long for its column is printed above the question instead, and the
    bracket says `[keep]`. Letting it push the colon out of line would ruin the one thing
    the columns are for - every answer the operator types starting in the same place - and
    truncating it would hide the difference between a prod host and a dev one.
    """
    if default and len(default) + 2 > DEFAULT_WIDTH:
        print(f"  {'':<4}{console.paint('current'.ljust(LABEL_WIDTH), 'dim')}{default}")
        bracket = "[keep]"
    else:
        bracket = f"[{default}]" if default else ""

    return f"  {number:<4}{label.ljust(LABEL_WIDTH)}{bracket.ljust(DEFAULT_WIDTH)}: "


def _complain(message: str) -> None:
    """Says what was wrong with an answer, where the answer was, and marked as a problem."""
    print(f"  {' ' * 4}{console.paint('! ' + message, 'warn')}")


def _ask(label: str, default: str | None = None, number: str = "") -> str:
    while True:
        try:
            answer = input(_prompt(label, default, number)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SetupAborted("cancelled at the prompt") from None
        if answer:
            return answer
        if default:
            return default
        _complain("this one is required")


def _ask_secret(label: str, *, keep_label: str | None, number: str = "") -> str | None:
    """Reads a password, showing a mask per character. None means "keep what we had".

    Masked rather than invisible: this prompt is met once, by someone pasting a password
    into an unfamiliar tool, and a terminal that shows no reaction at all is
    indistinguishable from one that has stopped listening.
    """
    while True:
        try:
            answer = prompt_for_secret(_prompt(label, keep_label, number))
        except (EOFError, KeyboardInterrupt):
            print()
            raise SetupAborted("cancelled at the prompt") from None
        if answer:
            return answer
        if keep_label:
            return None
        _complain("a password is required (the gateway does not support passwordless login)")


def _ask_provider(default: str, number: str = "") -> str:
    while True:
        answer = _ask("Database type", default, number).strip().lower()
        if answer in SUPPORTED_PROVIDERS:
            return answer
        if answer in PROVIDER_ALIASES:
            return PROVIDER_ALIASES[answer]
        if answer.isdigit() and 1 <= int(answer) <= len(SUPPORTED_PROVIDERS):
            return SUPPORTED_PROVIDERS[int(answer) - 1]
        _complain(f"choose a number, or one of: {', '.join(SUPPORTED_PROVIDERS)}")


def _ask_port(default: str, number: str = "") -> str:
    while True:
        answer = _ask("Port", default or None, number)
        if answer.isdigit() and 1 <= int(answer) <= 65535:
            return answer
        _complain("a port is a whole number between 1 and 65535")


def _ask_yes_no(question: str, *, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"{question} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False


def _parse_connection_url(answer: str) -> dict[str, str]:
    """Pulls host, port, database, user and password out of a pasted connection string.

    Understands `postgresql://user:pass@host:5432/db`, the `jdbc:` prefixed form of the
    same, and a bare `host:port`. Anything it does not recognise comes back empty, and the
    answer is then treated as a plain hostname — which is what it almost always is.
    """
    text = answer.strip()
    if not text:
        return {}

    if text.lower().startswith("jdbc:"):
        text = text[len("jdbc:") :]

    if "://" not in text:
        host, separator, port = text.partition(":")
        if separator and port.strip().isdigit():
            return {"host": host.strip(), "port": port.strip()}
        return {}

    try:
        parsed = urlsplit(text)
    except ValueError:
        return {}

    parts: dict[str, str] = {}
    if parsed.hostname:
        parts["host"] = parsed.hostname
    try:
        if parsed.port:
            parts["port"] = str(parsed.port)
    except ValueError:  # a non-numeric port in the pasted text
        pass
    database = parsed.path.lstrip("/").split("?", 1)[0]
    if database:
        parts["database"] = unquote(database)
    if parsed.username:
        parts["user"] = unquote(parsed.username)
    if parsed.password:
        parts["password"] = unquote(parsed.password)
    return parts


def _one_line(text: str, limit: int = 100) -> str:
    """Server banners are multi-line and long; one readable line is the useful part."""
    flattened = " ".join(text.split())
    return flattened if len(flattened) <= limit else flattened[: limit - 3] + "..."
