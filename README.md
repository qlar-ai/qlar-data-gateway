# Qlar Data Gateway

Let Qlar answer questions about your database **without opening a database port to the
internet, and without giving Qlar your database password.**

You run this small open-source process inside your own network. It makes an outbound
HTTPS connection to Qlar, asks whether there is a query to run, runs it read-only against
your database, and sends the rows back. Nothing connects *in*.

```
   your network                                  internet
 ┌───────────────────────────────┐
 │  ┌───────────┐   ┌─────────┐  │   outbound HTTPS only
 │  │ database  │◄──│ gateway │──┼──────────────────────────►  Qlar
 │  └───────────┘   └─────────┘  │   "any work for me?"
 │   credentials stay here       │   "here are the rows"
 └───────────────────────────────┘
        no inbound firewall rule, no public DNS, no certificate
```

| | Direct connection | With this gateway |
|---|---|---|
| Database port exposed to the internet | yes | **no** |
| Inbound firewall rule needed | yes | **no** |
| Database credentials stored by Qlar | yes | **no** — they stay in your `.env` |
| Queries auditable in your own systems | no | **yes** — local JSONL audit log |
| You decide which tables are reachable | in Qlar's UI | **also in your own config file** |

## What it will and will not run

The gateway assumes Qlar could be compromised and checks every statement itself:

- **Reads only.** Exactly one `SELECT`/`WITH` per job, parsed with a real SQL parser rather
  than pattern-matched, so comments and string literals cannot hide a second statement.
- **In a `READ ONLY` transaction**, enforced by your database, not by our code.
- **No escape hatches** — `COPY … FROM PROGRAM`, `pg_read_file`, `dblink`, `xp_cmdshell`,
  `OPENROWSET`, `INTO OUTFILE`, `LOAD_FILE`, `UTL_FILE` and friends are refused.
- **Optional table allowlist** in your own config: a compromise of Qlar still cannot read a
  table you never listed.
- **Every statement is logged locally**, with the agent, user and conversation that caused
  it, in a file that never leaves your premises.

Point it at a read-only database account anyway. That is the guarantee that does not
depend on our code being right — and `qlar-gateway test-db` warns you if the account
looks able to write.

**What it does not do:** the gateway closes the network exposure and the
credential-storage gap. It does not stop query *results* flowing to Qlar and into an AI
model — that is what the feature is for. If some columns must never leave, leave them out
of the allowlist.

## Requirements

- Python 3.11+, or Docker
- Outbound HTTPS (443) to your Qlar endpoint, and to github.com once, to fetch the release
- A database account with `SELECT` on the tables you want reachable
- A Qlar CMS user who can add a SQL Database Reader plugin

## Install

Docker (recommended — no Python on the host):

```bash
docker pull ghcr.io/pusakaai/data-gateway:0.2.0
```

Or with pip, installing only the driver you need. The wheel comes from the release rather
than from PyPI, where this package is not published:

```bash
pip install --upgrade "qlar-data-gateway[postgresql] @ https://github.com/pusakaai/data-gateway/releases/download/v0.2.0/qlar_data_gateway-0.2.0-py3-none-any.whl"
qlar-gateway version     # should print 0.2.0
```

Swap `postgresql` for `mysql`, `sqlserver`, `oracle` or `all`.

The `version` check is there because pip is quiet in the one case that looks like a
failure: asked for a version that is already installed, it downloads the wheel, installs
nothing, and prints no `Successfully installed` line to say so. Upgrading from an older
version does print one.

## Setup, start to finish

**1. Just start it.** With nothing configured yet, the first start asks — and proves the
answers with a real query before it goes any further:

```bash
qlar-gateway enroll
```

```
========================================================================
 Qlar Data Gateway — setup
========================================================================
Database
  1) postgresql  2) mysql  3) sqlserver  4) oracle
  Which one [postgresql]:
  Host or connection URL: db.internal
  Port [5432]:
  Database name: warehouse
  Username: qlar_readonly
  Password:

Qlar
  (ends in /api/data-gateway — the CMS gateway panel shows it)
  Qlar API endpoint: https://qlar.example.com/api/data-gateway

Saved to .env (mode 0600). The next start will not ask again.

Testing the database connection: postgresql://qlar_readonly@db.internal:5432/warehouse
  OK in 34 ms
  server: PostgreSQL 16.4 on x86_64-pc-linux-gnu

not enrolled yet (no gateway-state.json). Run: qlar-gateway enroll
```

The database half is now done and proved; the last line is step 2. Paste a whole
connection URL at the host question if you have one —
`postgresql://user:pass@db.internal:5432/warehouse` — and the remaining answers are filled
in from it for you to confirm.

The answers are written to `.env`, so this happens exactly once; `qlar-gateway run
--init` asks again, for the day the password rotates or the database moves. Prefer to
write the file yourself? Copy `.env.example` to `.env` and fill it in — then no question is
ever asked. And nothing changes for automation: without a terminal to ask on, a missing
setting is the same configuration error on stderr it has always been.

**2. Get a one-time enrolment code.** In the Qlar CMS: your agent → Plugins → SQL Database
Reader → *Connect via gateway*. Put it in `.env` as `QLAR_ENROLLMENT_CODE` (it expires in
15 minutes and works once).

**3. Enrol.** The CMS panel prints this line with both values already in it. This
generates your key pair — the private key is written to `gateway-key.pem` with mode `0600`
and never leaves the machine.

```bash
qlar-gateway enroll --base-url https://your-qlar-host/api/data-gateway --code K7P4-9WQX-2MTD
```

Neither value contains a space, so that line is the same in bash, cmd and PowerShell. The
endpoint is saved to `.env` for later starts; the code is not, because it is spent. Leave
either one out and you are asked for it instead — `qlar-gateway enroll` on its own still
works.

It prints a fingerprint, and then keeps running:

```
3A:7F:19:C4:...:C2

enrolled, waiting for approval in Qlar. Compare the key fingerprint above with the one
the CMS shows and click Approve; this starts working on its own, nothing else to run here.
```

**4. Approve it.** The CMS shows a fingerprint next to the hostname that just registered.
Check it matches the line above, character for character, then click **Approve**. This step
is what makes a stolen enrolment code useless on its own.

There is no step 5. Within a few seconds of the click the gateway says `approved. Serving
queries for ...` and starts answering. Every start re-checks the database first, so one that
cannot reach it says so on line one rather than looking healthy and failing every query.

Docker, which needs the fingerprint out of the logs because the container is detached:

```bash
docker run -d --name qlar-gateway --restart unless-stopped \
  --env-file .env -v "$PWD/state:/state" \
  ghcr.io/pusakaai/data-gateway:0.2.0 enroll

docker logs -f qlar-gateway   # read the fingerprint, approve, watch it connect
```

Stopping `docker logs` does not stop the gateway. Running that same `docker run` line again
after a restart re-uses the existing enrolment rather than trying to redeem a spent code.

Back in the CMS the gateway shows as online, and you continue with table detection as
normal. Full walkthrough including systemd and Kubernetes: [docs/INSTALL.md](docs/INSTALL.md).

## Commands

| Command | What it does |
|---|---|
| `qlar-gateway test-db` | verify the database settings without contacting Qlar |
| `qlar-gateway enroll` | register with Qlar and serve — the only command most people need |
| `qlar-gateway fingerprint` | print the key fingerprint to compare with the CMS |
| `qlar-gateway run` | serve, for a machine that is already enrolled |
| `qlar-gateway version` | release version and protocol version |

`run`, `test-db` and `enroll` take `--init`, which asks for the database details again and
rewrites `.env` even when it is already complete.

## Configuration

Everything is read from the environment, or from `.env` — which you can write by hand from
`.env.example`, or let the first run write for you. Real environment variables win, so a
container can override the file without editing it, and setting them all is how you skip
the questions entirely.

| Variable | Default | Purpose |
|---|---|---|
| `QLAR_BASE_URL` | — | your Qlar endpoint (required) |
| `QLAR_ENROLLMENT_CODE` | — | one-time code, only needed for `enroll` |
| `QLAR_GATEWAY_NAME` | hostname | label shown in the CMS |
| `DB_PROVIDER` | — | `postgresql`, `mysql`, `sqlserver`, `oracle` |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | — | connection details |
| `DB_OPT_*` | — | extra driver options, e.g. `DB_OPT_SSLMODE=verify-full` |
| `DB_STATEMENT_TIMEOUT_SECONDS` | `30` | server-side statement timeout |
| `MAX_RESULT_BYTES` | `10485760` | ceiling on one result |
| `MAX_CONCURRENT_QUERIES` | `5` | protects your database from a busy agent |
| `TABLE_ALLOWLIST` | empty | comma-separated; when set, nothing else is readable |
| `AUDIT_LOG_FILE` | `./audit/queries.jsonl` | local audit log; empty disables it |
| `POLL_TIMEOUT_SECONDS` | `25` | long-poll hold time |
| `GATEWAY_KEY_FILE` | `./gateway-key.pem` | private key location |
| `GATEWAY_STATE_FILE` | `./gateway-state.json` | gateway id + pinned Qlar public key |

## Operating notes

- **Restarting Qlar does not disconnect you.** There is no session to lose; the poll simply
  fails and is retried with backoff. Enrolment and approval live server-side.
- **Back up `gateway-key.pem`.** Losing it changes your fingerprint, which means enrolling
  and getting approved again.
- **Revoking** in the CMS takes effect on the gateway's next poll, which then exits.
- **Upgrades** are yours to schedule. The protocol version is separate from the release
  version. Qlar keeps accepting published protocol versions; protocol 1, which predates the
  gateway name, is the one exception and is refused with a message saying to upgrade.

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) — detailed install, systemd, Docker, Kubernetes, troubleshooting
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the complete wire contract
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) — what this defends against, and what it does not
- [docs/RELEASING.md](docs/RELEASING.md) — how a release is cut
- [CHANGELOG.md](CHANGELOG.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
