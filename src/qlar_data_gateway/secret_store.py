"""Where the database password comes from: the `.env` file, or an operating-system keystore.

By default the password is `DB_PASSWORD` in `.env` (or the real environment), exactly as
before. `DB_PASSWORD_SOURCE` moves it out of that file into something the operating system
protects, so a copy of `.env` - a backup, a support bundle, a misplaced `scp` - no longer
carries a working database credential:

    env            DB_PASSWORD (the default; unchanged behaviour)
    keyring        the OS credential store through the `keyring` package: Windows Credential
                   Manager, macOS Keychain, the Secret Service on a Linux desktop/server
                   (install the `[keystore]` extra)
    dpapi          a file sealed with Windows DPAPI for this user (or this machine), no extra
                   package needed
    systemd-creds  a systemd credential (`LoadCredentialEncrypted=`), decrypted by systemd
                   into $CREDENTIALS_DIRECTORY for this unit only
    file           a file holding only the password, e.g. a Docker or Kubernetes secret
                   mounted at /run/secrets/db_password

`qlar-gateway store-password` puts the password into the chosen store and, with
`--from-env`, takes it out of `.env` in the same step.

Every reader here returns the password and nothing else, and every error names the setting
to fix - never the value. Nothing in this module logs.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess  # noqa: S404 - only `systemd-creds encrypt`, with a fixed argument list
import sys
from collections.abc import Mapping, MutableMapping
from pathlib import Path

from .config import ConfigError

SOURCE_ENV = "env"
SOURCE_KEYRING = "keyring"
SOURCE_DPAPI = "dpapi"
SOURCE_SYSTEMD_CREDS = "systemd-creds"
SOURCE_FILE = "file"

PASSWORD_SOURCES = (SOURCE_ENV, SOURCE_KEYRING, SOURCE_DPAPI, SOURCE_SYSTEMD_CREDS, SOURCE_FILE)

# Sources `store-password` can write to. `file` is excluded on purpose: a file holding the
# password in clear is only an improvement when something else (Docker, Kubernetes, a
# secrets agent) provides and protects it, and that something is what writes it.
WRITABLE_SOURCES = (SOURCE_KEYRING, SOURCE_DPAPI, SOURCE_SYSTEMD_CREDS)

DEFAULT_KEYRING_SERVICE = "qlar-data-gateway"
DEFAULT_KEYRING_ENTRY = "db_password"
DEFAULT_DPAPI_FILE = "./db-password.dpapi"
DEFAULT_CREDENTIAL_NAME = "db_password"
DEFAULT_CREDENTIAL_FILE = "/etc/credstore.encrypted/db_password"

# Mixed into every DPAPI blob this gateway writes, so another program running as the same
# Windows user cannot hand our file to CryptUnprotectData and get the password back without
# also knowing this value. Not a secret - an application separator, which is what DPAPI's
# optional entropy is for.
DPAPI_ENTROPY = b"qlar-data-gateway/db-password/v1"

# First line of a DPAPI file, so a file of the wrong kind fails with a clear message rather
# than a Windows error code.
DPAPI_HEADER = "qlar-gateway-dpapi-v1"


def password_source(environ: Mapping[str, str] | None = None) -> str:
    """The configured `DB_PASSWORD_SOURCE`, validated. Unset means `env`."""
    env = os.environ if environ is None else environ
    source = (env.get("DB_PASSWORD_SOURCE") or "").strip().lower() or SOURCE_ENV
    if source not in PASSWORD_SOURCES:
        raise ConfigError(f"DB_PASSWORD_SOURCE must be one of {', '.join(PASSWORD_SOURCES)}, got {source!r}")
    return source


def resolve_db_password(environ: Mapping[str, str] | None = None) -> str:
    """Returns the database password from the configured source.

    `env` returns `DB_PASSWORD`, possibly empty: whether an empty password is acceptable is
    the caller's decision, and the caller's error message ("missing required database
    settings: DB_PASSWORD") stays exactly what it was before keystores existed.

    Every other source raises ConfigError when it cannot produce a non-empty password, and
    also when `DB_PASSWORD` is still set: a password both in `.env` and in a keystore means
    the move was never finished, and silently preferring either copy would hide that the
    plaintext one is still on disk.
    """
    env = os.environ if environ is None else environ
    source = password_source(env)

    if source == SOURCE_ENV:
        return env.get("DB_PASSWORD", "")

    if env.get("DB_PASSWORD"):
        raise ConfigError(
            f"DB_PASSWORD is set although DB_PASSWORD_SOURCE={source}. Remove DB_PASSWORD from "
            f".env (and from the environment) so the password exists only in the {source} store - "
            f"`qlar-gateway store-password --from-env` does both"
        )

    if source == SOURCE_KEYRING:
        password = _read_keyring(env)
    elif source == SOURCE_DPAPI:
        password = _read_dpapi(env)
    elif source == SOURCE_SYSTEMD_CREDS:
        password = _read_systemd_credential(env)
    else:
        password = _read_password_file(env)

    if not password:
        raise ConfigError(f"the database password from DB_PASSWORD_SOURCE={source} is empty")
    return password


def store_db_password(source: str, password: str, environ: Mapping[str, str] | None = None) -> str:
    """Writes the password into `source` and returns where it went, for the operator.

    The return value names a location (a keyring entry, a file path), never the password.
    """
    env = os.environ if environ is None else environ
    if source not in WRITABLE_SOURCES:
        raise ConfigError(
            f"store-password can write to {', '.join(WRITABLE_SOURCES)}; {source!r} is not one of them"
        )
    if not password:
        raise ConfigError("refusing to store an empty database password")

    if source == SOURCE_KEYRING:
        keyring = _keyring_module()
        service, entry = _keyring_names(env)
        try:
            keyring.set_password(service, entry, password)
        except Exception as error:  # noqa: BLE001 - every backend raises its own type
            raise ConfigError(
                f"could not write to the OS keyring ({type(error).__name__}). "
                "On a server without a desktop session, use dpapi (Windows) or systemd-creds (Linux)"
            ) from error
        return f"keyring service {service!r}, entry {entry!r}"

    if source == SOURCE_DPAPI:
        path = _dpapi_path(env)
        machine = _dpapi_machine_scope(env)
        blob = dpapi_protect(password.encode("utf-8"), machine_scope=machine)
        _write_private_file(path, f"{DPAPI_HEADER}\n{base64.b64encode(blob).decode('ascii')}\n")
        scope = "this machine" if machine else "this Windows user"
        return f"{path} (DPAPI, readable by {scope} only)"

    path = Path(env.get("DB_PASSWORD_CREDENTIAL_FILE") or DEFAULT_CREDENTIAL_FILE).expanduser()
    name = (env.get("DB_PASSWORD_CREDENTIAL") or DEFAULT_CREDENTIAL_NAME).strip()
    _systemd_creds_encrypt(name, password, path)
    return f"{path} (systemd credential {name!r})"


def remove_password_from_env(env_file: Path) -> bool:
    """Deletes every `DB_PASSWORD=` line from an env file. Returns whether one was there.

    Rewrites in place, keeping mode 0600, for the same bind-mount reason `write_env_values`
    gives. Comments and every other line are kept exactly as they were.
    """
    from .config import read_env_text

    if not env_file.exists():
        return False

    lines = read_env_text(env_file).splitlines()
    kept = [
        line
        for line in lines
        if not (
            (stripped := line.strip())
            and not stripped.startswith("#")
            and "=" in stripped
            and _env_key(stripped) == "DB_PASSWORD"
        )
    ]
    if len(kept) == len(lines):
        return False

    _write_private_file(env_file, "\n".join(kept) + "\n")
    return True


def forget_env_password(environ: MutableMapping[str, str] | None = None) -> None:
    """Drops DB_PASSWORD from this process's environment after it moved to a keystore."""
    env = os.environ if environ is None else environ
    env.pop("DB_PASSWORD", None)


# --- readers ----------------------------------------------------------------------------


def _read_keyring(env: Mapping[str, str]) -> str:
    keyring = _keyring_module()
    service, entry = _keyring_names(env)
    try:
        password = keyring.get_password(service, entry)
    except Exception as error:  # noqa: BLE001 - every backend raises its own type
        raise ConfigError(
            f"could not read the OS keyring ({type(error).__name__}). Check that a keyring backend "
            "is available to the account running the gateway"
        ) from error
    if password is None:
        raise ConfigError(
            f"no password in the OS keyring for service {service!r}, entry {entry!r}. "
            "Run `qlar-gateway store-password --source keyring` as the account that runs the gateway"
        )
    return password


def _read_dpapi(env: Mapping[str, str]) -> str:
    path = _dpapi_path(env)
    if not path.exists():
        raise ConfigError(
            f"DPAPI password file {path} does not exist. "
            "Run `qlar-gateway store-password --source dpapi` as the account that runs the gateway"
        )
    lines = path.read_text(encoding="utf-8").split()
    if len(lines) != 2 or lines[0] != DPAPI_HEADER:
        raise ConfigError(f"{path} is not a password file written by `qlar-gateway store-password`")
    try:
        blob = base64.b64decode(lines[1], validate=True)
    except ValueError as error:
        raise ConfigError(f"{path} is damaged (not valid base64)") from error
    return dpapi_unprotect(blob).decode("utf-8")


def _read_systemd_credential(env: Mapping[str, str]) -> str:
    directory = (env.get("CREDENTIALS_DIRECTORY") or "").strip()
    name = (env.get("DB_PASSWORD_CREDENTIAL") or DEFAULT_CREDENTIAL_NAME).strip()
    if not directory:
        raise ConfigError(
            "DB_PASSWORD_SOURCE=systemd-creds needs $CREDENTIALS_DIRECTORY, which systemd sets only "
            f"for a unit with `LoadCredentialEncrypted={name}:...` (see docs/INSTALL.md)"
        )
    path = Path(directory) / name
    if not path.exists():
        raise ConfigError(
            f"systemd credential {name!r} is not in $CREDENTIALS_DIRECTORY. "
            f"Add `LoadCredentialEncrypted={name}:<file>` to the unit, or set DB_PASSWORD_CREDENTIAL"
        )
    return _strip_one_newline(path.read_text(encoding="utf-8"))


def _read_password_file(env: Mapping[str, str]) -> str:
    raw = (env.get("DB_PASSWORD_FILE") or "").strip()
    if not raw:
        raise ConfigError("DB_PASSWORD_SOURCE=file needs DB_PASSWORD_FILE, the path of the password file")
    path = Path(raw).expanduser()
    if not path.is_file():
        raise ConfigError(f"DB_PASSWORD_FILE {path} is not a file this process can read")
    return _strip_one_newline(path.read_text(encoding="utf-8"))


# --- keyring ----------------------------------------------------------------------------


def _keyring_module():  # noqa: ANN202 - the optional `keyring` module
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as error:
        raise ConfigError(
            "DB_PASSWORD_SOURCE=keyring needs the keyring package: pip install 'qlar-data-gateway[keystore]'"
        ) from error
    return keyring


def _keyring_names(env: Mapping[str, str]) -> tuple[str, str]:
    service = (env.get("DB_PASSWORD_KEYRING_SERVICE") or DEFAULT_KEYRING_SERVICE).strip()
    entry = (env.get("DB_PASSWORD_KEYRING_ENTRY") or DEFAULT_KEYRING_ENTRY).strip()
    return service, entry


# --- DPAPI ------------------------------------------------------------------------------


def _dpapi_path(env: Mapping[str, str]) -> Path:
    return Path(env.get("DB_PASSWORD_DPAPI_FILE") or DEFAULT_DPAPI_FILE).expanduser()


def _dpapi_machine_scope(env: Mapping[str, str]) -> bool:
    scope = (env.get("DB_PASSWORD_DPAPI_SCOPE") or "user").strip().lower()
    if scope not in ("user", "machine"):
        raise ConfigError(f"DB_PASSWORD_DPAPI_SCOPE must be user or machine, got {scope!r}")
    return scope == "machine"


def dpapi_protect(data: bytes, *, machine_scope: bool = False) -> bytes:
    """Seals `data` with Windows DPAPI (CryptProtectData) and this application's entropy.

    User scope (the default) can only be opened by the same Windows account on the same
    machine. Machine scope can be opened by any account on this machine - use it only when
    the gateway runs as a service account that cannot hold a user profile.
    """
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if machine_scope:
        flags |= 0x4  # CRYPTPROTECT_LOCAL_MACHINE
    return _dpapi_call("CryptProtectData", data, flags)


def dpapi_unprotect(blob: bytes) -> bytes:
    """Opens a blob written by `dpapi_protect`, for the account (or machine) that sealed it."""
    return _dpapi_call("CryptUnprotectData", blob, 0x1)


def _dpapi_call(function: str, data: bytes, flags: int) -> bytes:
    if sys.platform != "win32":
        raise ConfigError("DB_PASSWORD_SOURCE=dpapi is only available on Windows")

    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob_of(value: bytes) -> tuple[DataBlob, ctypes.Array]:
        buffer = ctypes.create_string_buffer(value, len(value))
        return DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    data_in, _keep_in = blob_of(data)
    entropy, _keep_entropy = blob_of(DPAPI_ENTROPY)
    data_out = DataBlob()

    # Both functions share this signature: (in, description, entropy, reserved, prompt, flags, out).
    call = getattr(crypt32, function)
    ok = call(ctypes.byref(data_in), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(data_out))
    if not ok:
        code = ctypes.GetLastError()  # type: ignore[attr-defined]
        if function == "CryptUnprotectData":
            raise ConfigError(
                f"Windows could not open the DPAPI password file (error {code}). It can only be read "
                "by the account (or machine) that wrote it - run `qlar-gateway store-password "
                "--source dpapi` again as the account that runs the gateway"
            )
        raise ConfigError(f"Windows could not seal the password with DPAPI (error {code})")

    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(data_out.pbData)


# --- systemd-creds ----------------------------------------------------------------------


def _systemd_creds_encrypt(name: str, password: str, path: Path) -> None:
    """Runs `systemd-creds encrypt --name=<name> - <path>` with the password on stdin.

    On stdin, never on the command line, where every user on the machine could read it from
    the process list.
    """
    executable = shutil.which("systemd-creds")
    if executable is None:
        raise ConfigError(
            "systemd-creds was not found. It ships with systemd 250 and later; on older systems "
            "use DB_PASSWORD_SOURCE=file with a root-only file instead"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(  # noqa: S603 - fixed argument list, password on stdin
        [executable, "encrypt", f"--name={name}", "-", str(path)],
        input=password.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {completed.returncode}"
        raise ConfigError(f"systemd-creds encrypt failed: {reason} (it usually needs root)")


# --- helpers ----------------------------------------------------------------------------


def _write_private_file(path: Path, text: str) -> None:
    """Writes `text` to `path` with mode 0600 from the moment the file exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows, or a filesystem without modes
        pass


def _strip_one_newline(value: str) -> str:
    """Drops the single trailing newline `echo` and most editors add, and nothing else.

    A password may legitimately end in spaces; only the line ending is not part of it.
    """
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value


def _env_key(line: str) -> str:
    from .config import unwrap_quoted_line

    return unwrap_quoted_line(line).partition("=")[0].strip()
