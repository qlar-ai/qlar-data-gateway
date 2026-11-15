"""Command line: `qlar-gateway <command>`.

Six commands, in the order an operator meets them:

    test-db         check the database credentials before involving Qlar at all
    enroll          register with Qlar and serve — the only command most people need
    fingerprint     print this gateway's key fingerprint, to compare with the CMS
    run             serve, for a machine that is already enrolled
    store-password  move the database password out of .env into an OS keystore
    version         what is installed, and which protocol it speaks

`enroll` is the whole installation. It enrols if this machine is not enrolled yet, prints
the fingerprint to compare, and then stays up and polls — including through the wait for
someone to click Approve. Running it again on an enrolled machine skips enrolment and goes
straight to serving, which is what a container restart does. `run` remains for service
definitions that would rather not carry an enrolment step at all; it is the same loop.

`run`, `test-db` and `enroll` need database settings. When those are missing and there is
a terminal to ask on, the setup prompts in `wizard.py` collect them and write `.env`
instead of printing a configuration error — so a fresh install is `pip install` then
`enroll`, with nothing to read first. `--init` runs those prompts even when `.env` is
already complete. Without a terminal — a container, a systemd unit — nothing changes: the
same configuration error as before, on stderr, with the same exit code.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from dataclasses import replace
from pathlib import Path

from . import PROTOCOL_VERSION, __version__, console
from .config import (
    ConfigError,
    EnrollmentState,
    Settings,
    load_dotenv,
    load_settings,
    read_env_text,
    write_env_values,
)
from .crypto import fingerprint, load_or_create_private_key, public_key_pem
from .enroll import EnrollmentError, enroll
from .masked_input import prompt_for_secret
from .poll import PollLoop
from .secret_store import (
    SOURCE_SYSTEMD_CREDS,
    WRITABLE_SOURCES,
    password_source,
    remove_password_from_env,
    resolve_db_password,
    store_db_password,
)
from .wizard import SetupAborted, ask_enrollment_code, can_prompt, check_connection, run_setup

DEFAULT_ENV_FILE = ".env"

# The commands that need database settings, and so may offer the setup prompts.
SETUP_COMMANDS = ("run", "test-db", "enroll")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qlar-gateway",
        description="On-premise SQL access gateway for Qlar. Outbound-only: no inbound port is opened.",
    )
    parser.add_argument(
        "--env-file", default=DEFAULT_ENV_FILE, help="path to the settings file (default: .env)"
    )
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    parser.add_argument(
        "--version",
        action="version",
        version=f"qlar-gateway {__version__} (protocol {PROTOCOL_VERSION})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    _with_init_flag(
        subparsers.add_parser(
            "run", help="poll Qlar for jobs and execute them (already enrolled machines)"
        )
    )
    enroll_parser = _with_init_flag(
        subparsers.add_parser(
            "enroll",
            help="register this gateway with Qlar and start serving (the command to use)",
        )
    )
    # The two values that come from Qlar rather than from this machine. As arguments they
    # travel in one copy-paste line, identical in every shell - neither contains a space, so
    # nothing needs quoting, which is exactly what went wrong when they travelled through
    # `echo KEY=value >> .env` instead.
    enroll_parser.add_argument(
        "--base-url",
        help="the Qlar API endpoint, as the CMS gateway panel prints it (saved to .env)",
    )
    enroll_parser.add_argument(
        "--code",
        help="the one-time enrolment code from the CMS (single use; not saved)",
    )
    _with_init_flag(
        subparsers.add_parser("test-db", help="verify the database settings without contacting Qlar")
    )
    subparsers.add_parser("fingerprint", help="print this gateway's public key fingerprint")
    store_parser = subparsers.add_parser(
        "store-password",
        help="store the database password in an OS keystore instead of .env (DB_PASSWORD_SOURCE)",
    )
    store_parser.add_argument(
        "--source",
        choices=WRITABLE_SOURCES,
        help="where to store it (default: DB_PASSWORD_SOURCE from .env)",
    )
    store_parser.add_argument(
        "--from-env",
        action="store_true",
        help="move the DB_PASSWORD already in .env instead of asking for it, and delete it from .env",
    )
    subparsers.add_parser("version", help="print version and protocol information")

    args = parser.parse_args(argv)
    console.make_output_safe()
    _configure_logging(args.log_level)

    if args.command == "version":
        print(f"qlar-gateway {__version__}")
        print(f"protocol {PROTOCOL_VERSION}")
        return 0

    if args.command == "store-password":
        # Before _settings_for: moving the password must work while the settings are
        # incomplete - with DB_PASSWORD_SOURCE set and no password stored yet, they are.
        return _command_store_password(Path(args.env_file), args.source, args.from_env)

    settings, connection_ok = _settings_for(args)
    if settings is None:
        return 2

    if args.command == "test-db":
        return _command_test_db(settings, connection_ok)
    if args.command == "fingerprint":
        return _command_fingerprint(settings)
    if args.command == "enroll":
        return _command_enroll(
            settings, Path(args.env_file), getattr(args, "code", None), connection_ok
        )
    if args.command == "run":
        return _command_run(settings, connection_ok)

    return 2


def _with_init_flag(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument(
        "--init",
        "-init",
        action="store_true",
        help="ask for the database details again, even when .env is already filled in",
    )
    return parser


def _settings_for(args: argparse.Namespace) -> tuple[Settings | None, bool | None]:
    """Loads the settings, running the setup prompts when that is the helpful thing to do.

    Returns the settings and whether the database connection has already been tested:
    True or False when the prompts tested it, None when nothing has been checked yet. That
    third state is what stops `run` from opening two connections to say the same thing.
    """
    env_file = Path(args.env_file)

    # An endpoint given on the command line is the answer to a question the prompts would
    # otherwise ask, so it is applied before anything reads the environment.
    base_url = (getattr(args, "base_url", None) or "").strip().rstrip("/")
    if base_url:
        os.environ["QLAR_BASE_URL"] = base_url

    if getattr(args, "init", False):
        if not can_prompt():
            print(
                "--init needs a terminal to ask on. Edit .env directly, or run the container "
                "interactively (docker run -it ... run --init).",
                file=sys.stderr,
            )
            return None, None
        return _run_setup(env_file, ask_endpoint=not base_url)

    try:
        return load_settings(env_file), None
    except ConfigError as error:
        if args.command not in SETUP_COMMANDS or not can_prompt():
            print(f"configuration error: {error}", file=sys.stderr)
            return None, None

        # First run, most likely: no .env at all, or one that was never filled in. Ask
        # rather than explain, since everything the explanation would say is a question -
        # but carry the reason into the form, where it answers "why am I being asked?".
        return _run_setup(env_file, ask_endpoint=not base_url, reason=str(error))


def _run_setup(
    env_file: Path, *, ask_endpoint: bool = True, reason: str = ""
) -> tuple[Settings | None, bool | None]:
    try:
        return run_setup(env_file, ask_endpoint=ask_endpoint, reason=reason)
    except SetupAborted as error:
        print(f"setup cancelled: {error}", file=sys.stderr)
        return None, None


def _command_test_db(settings: Settings, connection_ok: bool | None) -> int:
    # The check itself lives with the setup prompts: it is the same paragraph of output
    # there and here, and an operator comparing the two should not have to wonder whether
    # they mean the same thing.
    if connection_ok is None:
        connection_ok = check_connection(settings, prominent=True)
    return 0 if connection_ok else 1


def _command_store_password(env_file: Path, source: str | None, from_env: bool) -> int:
    """Puts the database password into an OS keystore and points `.env` at it.

    In this order, so that a failure at any step leaves a working configuration: store the
    password, read it back, then set DB_PASSWORD_SOURCE and delete DB_PASSWORD from `.env`.
    """
    try:
        load_dotenv(env_file)
        chosen = source or password_source()
    except ConfigError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 2

    if chosen not in WRITABLE_SOURCES:
        print(
            f"choose where to store it: --source {' | '.join(WRITABLE_SOURCES)} "
            "(or set DB_PASSWORD_SOURCE in .env)",
            file=sys.stderr,
        )
        return 2

    if from_env:
        password = os.environ.get("DB_PASSWORD", "")
        if not password:
            print(f"DB_PASSWORD is not set in {env_file}; run without --from-env to type it", file=sys.stderr)
            return 2
    else:
        if not can_prompt():
            print("store-password needs a terminal to ask on, or --from-env", file=sys.stderr)
            return 2
        try:
            password = prompt_for_secret("  Database password: ")
            again = prompt_for_secret("  Same again:        ")
        except (EOFError, KeyboardInterrupt):
            print()
            print("cancelled", file=sys.stderr)
            return 2
        if not password:
            print("a password is required", file=sys.stderr)
            return 2
        if password != again:
            print("the two entries differ; nothing was stored", file=sys.stderr)
            return 1

    try:
        where = store_db_password(chosen, password)
    except ConfigError as error:
        print(f"could not store the password: {error}", file=sys.stderr)
        return 1

    # systemd decrypts the credential only inside the unit that loads it, so it cannot be
    # read back from here; every other store is checked before .env stops carrying the
    # password.
    if chosen != SOURCE_SYSTEMD_CREDS:
        environ = {key: value for key, value in os.environ.items() if key != "DB_PASSWORD"}
        environ["DB_PASSWORD_SOURCE"] = chosen
        try:
            readable = resolve_db_password(environ) == password
        except ConfigError as error:
            print(f"stored, but could not be read back: {error}", file=sys.stderr)
            return 1
        if not readable:
            print("stored, but what was read back differs; .env left unchanged", file=sys.stderr)
            return 1

    write_env_values(env_file, {"DB_PASSWORD_SOURCE": chosen})
    removed = remove_password_from_env(env_file)
    os.environ.pop("DB_PASSWORD", None)

    console.field("stored in", where)
    console.field("env file", f"{env_file}: DB_PASSWORD_SOURCE={chosen}")
    if removed:
        console.detail(f"DB_PASSWORD removed from {env_file}")
    if chosen == SOURCE_SYSTEMD_CREDS:
        console.detail(
            "add to the gateway's unit:  LoadCredentialEncrypted="
            f"{os.environ.get('DB_PASSWORD_CREDENTIAL') or 'db_password'}:{where.split(' ')[0]}"
        )
    console.detail("a real DB_PASSWORD environment variable, if one is set, must be removed too")
    return 0


def _command_fingerprint(settings: Settings) -> int:
    private_key, created = load_or_create_private_key(settings.key_file)
    if created:
        print(f"generated a new key pair at {settings.key_file}")
    print(fingerprint(public_key_pem(private_key)))
    return 0


def _command_enroll(
    settings: Settings, env_file: Path, code: str | None = None, connection_ok: bool | None = None
) -> int:
    """Makes sure this machine is enrolled, then serves queries. One command, start to finish.

    There used to be a second one. `enroll` printed a fingerprint and exited, and the operator
    was told to come back and type `run` after clicking Approve — a handover across a wait of
    unknown length, in a different window, often on a different day. People missed it, and the
    gateway that Qlar showed as approved was simply not running.

    So enrolment now flows straight into the poll loop, which has always tolerated not being
    approved yet and now says so in words. Approving in Qlar is the last thing anyone has to do.

    It is also idempotent, which is what makes it safe to be the only command: a machine that is
    already enrolled skips enrolment and goes straight to work. That is what a container restart
    does, and what an operator restarting a gateway that died should be able to do without
    hunting for a code that was single-use and is long gone.
    """
    if code:
        settings = replace(settings, enrollment_code=code.strip().strip("\"'").upper())

    # Whatever route the endpoint arrived by, later starts read it from the file.
    _remember_base_url(settings, env_file)

    state = EnrollmentState.load(settings.state_file)
    if state is not None and state.base_url == settings.base_url:
        # Already ours. Enrolling again is not just unnecessary, it is impossible: the code was
        # redeemed once and Qlar keeps only a hash of it.
        console.banner(f"Qlar Data Gateway {__version__}")
        console.field("endpoint", settings.base_url)
        console.field("gateway id", state.gateway_id)
        console.detail("already enrolled; starting")
        return _serve(settings, state, connection_ok)

    # The code was the one answer the setup prompts did not cover, so it had to be typed
    # into `.env` by hand - and the instructions for doing that are shell-specific in a way
    # that bites on Windows, where `echo 'KEY=value'` writes the quotes into the file. A
    # prompt has no shell in it.
    if settings.enrollment_code is None and can_prompt():
        try:
            settings = replace(settings, enrollment_code=ask_enrollment_code())
        except SetupAborted as error:
            print(f"cancelled: {error}", file=sys.stderr)
            return 2

    try:
        state, key_fingerprint = enroll(settings)
    except EnrollmentError as error:
        print(f"enrolment failed: {error}", file=sys.stderr)
        return 1

    console.banner("Enrolled. One thing left: approve this gateway in the Qlar CMS.")
    console.field("gateway id", state.gateway_id)
    console.field("state file", settings.state_file)
    print()
    console.heading("KEY FINGERPRINT -- compare with the one the CMS shows")
    print()
    console.fingerprint_block(key_fingerprint)
    print()
    console.step(1, "CMS -> your agent -> Plugins -> SQL Database Reader")
    console.step(2, "check the fingerprint matches, then click Approve")
    console.step(3, "nothing. This keeps running and starts working when you do.")
    print()
    return _serve(settings, state, connection_ok)


def _remember_base_url(settings: Settings, env_file: Path) -> None:
    """Writes QLAR_BASE_URL to the env file when it is not already there.

    `--base-url` is given once, at enrolment, but every later `run` needs it. Leaving it in
    the environment of a process that is about to exit would mean the next start asks for
    an endpoint the operator has already supplied - which is the complaint this whole path
    exists to answer.
    """
    try:
        load_dotenv(env_file)
    except ConfigError:
        return  # unreadable file: the setup prompts deal with it, not this

    if os.environ.get("QLAR_BASE_URL") == settings.base_url and _env_file_has(env_file, "QLAR_BASE_URL"):
        return

    write_env_values(env_file, {"QLAR_BASE_URL": settings.base_url})


def _env_file_has(env_file: Path, key: str) -> bool:
    if not env_file.exists():
        return False
    try:
        return any(
            line.partition("=")[0].strip() == key
            for raw in read_env_text(env_file).splitlines()
            if (line := raw.strip()) and not line.startswith("#") and "=" in line
        )
    except ConfigError:
        return False


def _command_run(settings: Settings, connection_ok: bool | None) -> int:
    console.banner(f"Qlar Data Gateway {__version__}")
    console.field("endpoint", settings.base_url)

    state = EnrollmentState.load(settings.state_file)
    if state is None:
        print(
            f"not enrolled yet (no {settings.state_file}). Run: qlar-gateway enroll",
            file=sys.stderr,
        )
        return 2

    console.field("gateway id", state.gateway_id)

    if state.base_url != settings.base_url:
        print(
            f"QLAR_BASE_URL ({settings.base_url}) does not match the URL this gateway enrolled "
            f"against ({state.base_url}). Re-enrol if the Qlar endpoint really changed.",
            file=sys.stderr,
        )
        return 2

    return _serve(settings, state, connection_ok)


def _serve(settings: Settings, state: EnrollmentState, connection_ok: bool | None) -> int:
    """Checks the database, then polls until stopped or revoked.

    Shared by `run` and `enroll`, which differ only in how they got hold of the enrolment.
    """
    # A gateway that polls happily while every query fails looks healthy in the CMS, and that
    # is the most confusing way for an installation to be broken.
    if connection_ok is None:
        connection_ok = check_connection(settings)
    if not connection_ok:
        console.warning(
            "Starting anyway",
            "The database may simply be down at this moment, and the gateway reports its",
            "state to Qlar on every poll, so the CMS shows the data source as unreachable.",
            "",
            "Run `qlar-gateway run --init` to re-enter the connection details.",
            file=sys.stderr,
        )

    print()
    print("  Polling for work. Ctrl-C stops it; jobs already running finish first.")
    print()

    loop = PollLoop(settings, state)

    def _handle_signal(signum, _frame):  # noqa: ANN001 - signal handler signature
        logging.getLogger("qlar_data_gateway").info("received signal %s, finishing in-flight jobs", signum)
        loop.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    loop.run_forever()
    return 0


def _configure_logging(level: str) -> None:
    resolved = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=resolved,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    # httpx logs every request at INFO, which put "POST .../enroll 200 OK" in the middle of
    # the one screen an operator reads carefully. Their own logs are wanted when someone is
    # debugging and noise otherwise, so they follow LOG_LEVEL down to DEBUG and no further.
    if resolved > logging.DEBUG:
        for library in ("httpx", "httpcore"):
            logging.getLogger(library).setLevel(logging.WARNING)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
