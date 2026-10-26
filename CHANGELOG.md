# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **protocol version** is tracked separately from the release version — see
[docs/PROTOCOL.md](docs/PROTOCOL.md §7). A release that does not change the wire format
does not change the protocol version.

## [Unreleased]

## [0.2.1] - 2026-10-26

### Changed

- **Licence.** Relicensed from MIT to the Apache License, Version 2.0.

## [0.2.0] - 2026-09-20

**The wrapper is now the Qlar Data Gateway.** "Wrapper" names a thin adapter over a library;
this is a policy enforcement point that runs inside your network, pulls work outbound, decides
what SQL may execute and holds the credentials Qlar is deliberately not given. The old name
said nothing about locality, direction or safety - the three reasons anyone installs it - and
`db-` locked a generic channel to databases.

Everything below is a rename. No behaviour changed, nothing was added, and nothing was fixed.

### Changed - BREAKING

- **Package, command and image.** Distribution `qlar-db-wrapper` is now `qlar-data-gateway`,
  the module `qlar_db_wrapper` is `qlar_data_gateway`, the command `qlar-db-wrapper` is
  `qlar-gateway`, and the image `ghcr.io/pusakaai/db-wrapper` is
  `ghcr.io/pusakaai/data-gateway`. The repository moved to `pusakaai/data-gateway`; GitHub
  redirects the old URL, GHCR does not - the old image stays published under the old name.
- **Configuration.** `WRAPPER_KEY_FILE`, `WRAPPER_STATE_FILE` and `QLAR_WRAPPER_NAME` are now
  `GATEWAY_KEY_FILE`, `GATEWAY_STATE_FILE` and `QLAR_GATEWAY_NAME`; the files they default to
  are `gateway-key.pem` and `gateway-state.json`. `QLAR_BASE_URL`, `QLAR_ENROLLMENT_CODE` and
  every `DB_*` setting are unchanged - but the endpoint `QLAR_BASE_URL` points at ends in
  `/api/data-gateway`, not `/api/db-wrapper`.
- **Protocol 2.** The caller's header `X-Qlar-Wrapper-Id` is now `X-Qlar-Gateway-Id`. That is
  an incompatible change to the wire format, so the protocol version moves to 2 - see
  [docs/PROTOCOL.md](docs/PROTOCOL.md) section 7. Protocol 1 is withdrawn rather than kept
  alive: it was never part of a production deployment, and Qlar now refuses it by name, with a
  message saying to upgrade, instead of accepting an enrolment that would then fail every
  signed request invisibly.
- **No compatibility shims.** The old environment variables are not read, the old key file is
  not picked up, and the old endpoint is not served. A machine that ran 0.1.x therefore
  generates a fresh key pair, gets a new fingerprint, and must enrol and be approved again.

### Upgrading from 0.1.x

Reinstall as 0.2.0, point `QLAR_BASE_URL` at `/api/data-gateway`, rename the three environment
variables, enrol with a fresh code and approve the new fingerprint in the CMS. Delete the
leftover `wrapper-key.pem` and `wrapper-state.json`; they are no longer read by anything.

## [0.1.7] - 2026-09-20

One command installs a wrapper. `enroll` no longer hands the operator back to a second
command they had to remember to run after someone else clicked a button.

### Changed

- **`enroll` enrols and then serves.** It prints the fingerprint to compare, stays up, and
  starts answering queries the moment the wrapper is approved in Qlar. The old flow ended
  at "come back here and run: qlar-db-wrapper run" - a handover across a wait of unknown
  length, usually in a different window and often on a different day. It was missed often
  enough that "the CMS says approved but nothing works" became the common failure report.
- **`enroll` is idempotent.** A machine that is already enrolled against the same endpoint
  skips enrolment and goes straight to serving. This is what makes it safe as the only
  command: a container restart re-runs it, and an operator whose wrapper died can run the
  same line again without hunting for a code that was single-use and is long gone.
- **Waiting for approval is no longer reported as a failure.** `403 pending_approval` now
  raises `AwaitingApproval` and is logged once, at INFO, in words: "enrolled, waiting for
  approval in Qlar ... this starts working on its own, nothing else to run here." Before,
  it fell through to the generic branch and printed `Qlar rejected the poll: HTTP 403:
  Forbidden` every few seconds with the word "approval" nowhere on screen - which is
  exactly why operators killed the process and then had to be told to start it again.
- **Approval is picked up in seconds.** Waiting uses a steady 4-second interval rather than
  the error backoff, which had stretched to 15 seconds by the time anyone clicked. A
  person is looking at a fingerprint; the wrapper should not make them wonder.
- **The first successful poll after a wait says so**: "approved. Serving queries for ...".

### Unchanged

- `run` still exists and is still the same loop, for service definitions that would rather
  not carry an enrolment step. Nothing that runs today needs changing.
- `revoked` is still the one refusal that stops the wrapper, and every other rejection is
  still retried with the same backoff. Only the two states an operator can act on are
  named.

## [0.1.6] - 2026-09-20

Everything an operator reads on screen, rewritten around a screenshot of someone who had
just enrolled successfully and could not tell what to do next.

### Changed

- **The enrolment result says what to do.** A ruled heading, the wrapper id and state file
  in columns, and three numbered steps. The fingerprint - the one check standing between a
  stolen enrolment code and someone's database - is printed as four blocks of eight bytes
  over two lines, in the shape a card number is printed in and for the same reason: 95
  unbroken characters is a fingerprint nobody actually compares.
- **`run` opens with a block, not a log stream**: endpoint, wrapper id, database,
  connection, server version, then one line saying it is polling.
- **The setup form is numbered and aligned.** `1/7` through `7/7`, so an operator filling
  it in knows how much is left, and one column for every answer, so what they typed can be
  read back down the page. A default too long for its column moves to a `current` line
  above rather than pushing the colon out of line - truncating it would hide the
  difference between a prod host and a dev one.
- **The connection test is the loudest thing on the setup screen**, under its own rule,
  with `[ OK ]` or `[FAIL]` at the start of the line.
- **The over-privileged-account warning is its own block**, with the SQL to create a
  read-only role. Set in the same shape as the success it follows, it read as more success.
- **Colour**, when the terminal has it: green for a good result, yellow for a warning, red
  for a failure, bold for the fingerprint. Off when `NO_COLOR` is set, when `TERM=dumb`,
  and when output is not a terminal. On Windows the console is asked to interpret escape
  codes and colour is dropped if it will not.

### Fixed

- **`enroll` could crash on a Windows console.** The prompt telling an operator where to
  find their enrolment code contained an arrow, which cp1252 cannot encode; cp437 cannot
  encode an em dash either, and several messages had one. Every string that may be printed
  is ASCII now, a test enforces it, and `stdout`/`stderr` are set to replace rather than
  raise so the next stray character cannot stop the process.
- **`httpx` no longer logs a request line into the middle of the enrolment result.**
  Third-party loggers follow `LOG_LEVEL` down to DEBUG and are quiet above it.
- A failed connection check prints its whole block to stderr. Half on each stream
  interleaved into nonsense as soon as one was redirected.

## [0.1.5] - 2026-09-20

### Added

- **`enroll --base-url ... --code ...`.** The two values that come from Qlar rather than
  from the machine the wrapper runs on now travel as arguments, which means the CMS can
  print one line to copy. It reads the same in bash, cmd and PowerShell, because neither
  value contains a space and so nothing needs quoting — which is precisely what went wrong
  when they travelled through `echo KEY=value >> .env` instead.

  The endpoint is written to `.env` so later starts have it; the code is not, because it is
  single use and spent. Omit either and the prompts ask for it as before.

  The database is still asked for. It is the one thing nothing on this path can know.

## [0.1.4] - 2026-09-20

### Changed

- **The password prompt shows a `*` per character.** It echoed nothing, which is the right
  default for a login someone types every day and the wrong one here: this prompt is met
  once, by an operator pasting a database password into a tool they installed five minutes
  ago, and a terminal showing no reaction is indistinguishable from one that has stopped
  listening. Backspace works, Ctrl-C still cancels, and a terminal that cannot be driven
  character by character falls back to the old echo-free prompt rather than failing.

  It is a trade: the length of the password is now visible to someone looking at the
  screen, which `getpass` did not reveal. The smaller risk of the two.

### Fixed

- **The pip line now says `--upgrade`, and is followed by a version check.** Asked for a
  version that is already installed, pip downloads the wheel, installs nothing, and prints
  no `Successfully installed` to say so — which reads exactly like a failed upgrade. The
  check answers it in one line, and `--upgrade` covers older pip, where a direct URL could
  count as satisfied by any installed version of the same name.

## [0.1.3] - 2026-09-20

### Added

- **The setup prompts say what they read from the file**, by key name, before asking for
  anything. Being asked for a setting that is already written down is infuriating, and the
  three reasons it happens — the file is in another directory, its encoding cannot be read,
  or the line is not a setting — look identical from the outside. Names only, never values:
  one of those keys is a database password.

## [0.1.2] - 2026-09-20

Everything here came from one operator installing the wrapper on Windows and following the
instructions exactly. The instructions were written for a POSIX shell; the machine was not.

### Added

- **`enroll` asks for the one-time code** when it is not configured and there is a terminal
  to ask on. It was the only answer the setup prompts did not cover, so it had to be typed
  into `.env` by hand — and that is the step where the shell gets involved. A pasted code
  keeps working; quotes and case are tidied up on the way through.

### Fixed

- **A `.env` written by `cmd.exe` is now read.** `echo 'KEY=value' >> .env` is correct in a
  POSIX shell and a trap in cmd, which has no single-quote quoting and writes the quotes
  into the file. The result was a key named `'KEY`, so the wrapper reported a setting as
  unset while the operator was looking straight at it. A line wrapped in quotes is now
  unwrapped; a *value* wrapped in quotes still means what it always did.
- **A UTF-8 BOM no longer becomes part of the first key.** Several Windows editors write
  one, and it is invisible on screen.
- **UTF-16 is named instead of crashing.** PowerShell 5.1's `>>` writes it, and the loader
  used to raise `UnicodeDecodeError` out of a config file. It now says what the encoding is
  and what to do about it.
- **An unreadable `.env` is never silently overwritten.** The setup prompts move it aside
  to `.env.bak` and say so; whatever was in it was put there by someone.
- **The pip instructions named a package that is not on PyPI.** `pip install
  "qlar-db-wrapper[postgresql]"` answers `No matching distribution found`: the release
  workflow builds the wheel and attaches it to the GitHub release, and never publishes it
  anywhere else. README and `docs/INSTALL.md` now install from the release asset, which
  works today. If the package is ever published to PyPI, the short form comes back.

## [0.1.1] - 2026-09-20

The first published release. 0.1.0 was tagged in the changelog but never cut, so the
artifacts and images below are the first that exist.

### Added

- **Setup prompts on first run.** `run`, `test-db` and `enroll` started without usable
  configuration now ask for the database details — provider, host, port, database, user,
  password, and the Qlar endpoint — and write them to `.env` with mode 0600, so installing
  the wrapper and starting it is the whole job. A connection URL pasted at the host
  question fills in the rest. Only when there is a terminal to ask on: a container without
  `-it`, a systemd unit and CI get exactly the configuration error they got before.
- **`--init`** on those three commands, which asks again over a complete `.env` — for a
  rotated password or a moved database. The file is rewritten in place, so hand-added
  settings and comments survive.
- **A test query at every start**, not only in `test-db`. A wrapper that polls happily
  while every query fails looks healthy in the CMS, which is the most confusing way for an
  installation to be broken. `run` reports the database and its server version on line one,
  and keeps running if it is merely down for the moment.

### Changed

- `.env` values may be quoted, and a quoted value now loses exactly one surrounding pair
  rather than every quote character — so a password with a leading space, a `#` or a
  trailing quote survives the round trip.
- **`QLAR_BASE_URL` no longer has a default.** The endpoint differs per Qlar deployment and
  the CMS wrapper panel prints the right one, so the setup prompts ask for it instead of
  offering a guess. `https://plugins.qlar.ai/api/db-wrapper`, which appeared throughout the
  documentation as though it were known, serves a website and never was an API endpoint.

### Fixed

- **A wrong `QLAR_BASE_URL` is now reported as a wrong URL.** Web servers answer a signed
  POST cheerfully: a static site returns `405` with an HTML page, a host where the feature
  is not deployed returns an empty `404`. Enrolment turned the second into "Qlar rejected
  the enrolment code — generate a fresh one", sending operators back to the CMS for codes
  that failed identically, and `run` logged the first as `Qlar rejected the poll` every few
  seconds forever. An HTML body at any status, or a `404` carrying no JSON, is now
  `QlarNotAnEndpoint` and says which URL answered, what it answered with, and where the
  right value is written down.

## [0.1.0] - 2026-09-19

Never published: no tag, no image, no release artifacts. Kept here because it is what the
code was before 0.1.1, and because deleting history to tidy it up is its own kind of lie.
Protocol version 1.

### Added

- **Outbound-only operation.** The wrapper long-polls Qlar for jobs over HTTPS and never
  listens on a port, so no inbound firewall rule, public DNS name or TLS certificate is
  needed on the customer's side.
- **Database credentials stay on-premise.** They live only in the operator's `.env`; Qlar
  never receives or stores them.
- **Mutual payload signatures** (ECDSA P-256 / SHA-256). The wrapper signs every request
  over method, path, timestamp, nonce and a body hash; Qlar signs every job, which the
  wrapper verifies against a public key pinned at enrolment — so a TLS-terminating proxy
  inside the customer's network cannot inject or rewrite SQL.
- **Enrolment with a one-time code**, plus a human fingerprint approval step in the CMS.
  The key pair is generated on the customer's machine and the private key never leaves it.
- **SQL guard**: exactly one parsed `SELECT`/`WITH` per job, dialect-aware refusal of file,
  shell and network escape hatches, and an optional table allowlist that lives in the
  customer's own config file.
- **`READ ONLY` transactions** and a server-side statement timeout on every job.
- **Four providers**: PostgreSQL, MySQL/MariaDB, SQL Server and Oracle, each installable as
  a separate extra so an installation only pulls the driver it uses.
- **Columnar result encoding** with lossless type rules — decimals and integers beyond
  2^53 as strings, ISO-8601 timestamps, `base64:`-prefixed binary — plus row and byte
  ceilings.
- **Error envelope carrying the raw driver code** (SQLSTATE or error number), so Qlar can
  classify failures by code rather than by message text.
- **Local JSONL audit log** recording every statement with the agent, user and
  conversation that caused it. It never leaves the customer's premises.
- `test-db`, `enroll`, `fingerprint`, `run` and `version` commands, a Docker image, and
  systemd/Kubernetes deployment guides.

[Unreleased]: https://github.com/qlar-ai/qlar-data-gateway/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/qlar-ai/qlar-data-gateway/releases/tag/v0.2.1
[0.2.0]: https://github.com/pusakaai/data-gateway/releases/tag/v0.2.0
[0.1.7]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.7
[0.1.6]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.6
[0.1.5]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.5
[0.1.4]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.4
[0.1.3]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.3
[0.1.2]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.2
[0.1.1]: https://github.com/pusakaai/data-gateway/releases/tag/v0.1.1
