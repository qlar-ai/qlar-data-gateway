# Security model

What this gateway defends against, how, and — just as important — what it does not
defend against. If you are reviewing this software before letting it into your network,
this page is written for you.

## The problem it solves

Without the gateway, Qlar connects directly to your database over the internet. That
requires two things many organisations will not agree to:

1. **A database port reachable from Qlar's cloud.** Even restricted by IP, the listening
   service is your RDBMS — a large, complex piece of software you did not write, exposed
   to a network you do not control.
2. **Your database credentials stored in Qlar's systems.** They are needed on every query,
   so they live in Qlar's database.

With the gateway, neither is true. The only connection is outbound, and the credentials
never leave your `.env`.

## Trust boundaries

| Party | Trusted with |
|---|---|
| **You** | the database credentials, the private key, the allowlist, the audit log |
| **The gateway** | executing exactly one read per job, inside your network |
| **Qlar** | producing SQL. **Not** trusted to be uncompromised |

The last line is the design premise. Every check below assumes Qlar's cloud could be
hostile — because if the only protection were Qlar's own validation, running a gateway
would buy you nothing over a direct connection.

## Controls

### Network

- No listening socket. No inbound firewall rule, no public DNS name, no TLS certificate to
  obtain or renew.
- Outbound HTTPS only, to the single host you configure, with certificate verification on.
  (`QLAR_INSECURE_SKIP_TLS_VERIFY` exists for local testing and is named so it looks wrong
  in a production file.)

### Identity

- The gateway generates an ECDSA P-256 key pair **on your machine** at first run. The
  private key is written mode `0600` and is never transmitted. The gateway refuses to start
  if that file is group- or world-readable.
- Every request to Qlar is signed over method, path, timestamp, nonce and a hash of the
  body — so nothing in it can be altered in transit, and a captured request cannot be
  replayed (±120 s skew window, nonce cache).
- Every job from Qlar is signed by Qlar and verified against the public key pinned at
  enrolment. **A proxy inside your own network that terminates TLS cannot inject or rewrite
  SQL.**
- Enrolment codes are single use, expire in 15 minutes, and are stored hashed. A code alone
  is not enough: an administrator must approve the key fingerprint, which a thief's gateway
  would not match.

### What may be executed

Four independent layers, weakest to strongest:

1. **Parsed, not pattern-matched.** Exactly one statement, and it must be a `SELECT`/`WITH`.
   Using a real SQL parser means comments, string literals and whitespace cannot smuggle a
   second statement past the check. SQL that fails to parse is refused, not guessed at.
2. **Escape hatches refused.** `COPY … FROM/TO PROGRAM`, `pg_read_file`, `lo_import`,
   `dblink`, `xp_cmdshell`, `OPENROWSET`, `sp_OA*`, `INTO OUTFILE`, `LOAD_FILE`, `UTL_FILE`,
   `UTL_HTTP`, `DBMS_*` and similar — the constructs that turn a read into a file read, a
   shell command or an outbound network call.
3. **Your table allowlist.** Optional but recommended. It lives in your config file, not in
   Qlar, so no change on Qlar's side can widen it.
4. **`READ ONLY` transactions and a read-only account.** Enforced by your database. This
   layer holds even if every layer above it has a bug.

Schema discovery (`introspect`) is confined to catalog objects — `information_schema`,
`pg_catalog`, `sys.*`, Oracle's `USER_*` views — so it cannot be used to read business data
under cover of "looking at the schema".

**Parquet files** (`DB_PROVIDER=parquet`) have no database to enforce anything, so the layers
are rearranged. The gateway itself decides which files exist and what each table is called,
and a statement may only name those tables: table functions (`read_parquet`, `read_csv`,
`glob`, `query`, ...), file paths in `FROM`, and `COPY`/`ATTACH`/`INSTALL`/`PRAGMA`/`SET` are
refused by the parser layer. The DuckDB instance is then locked — `allowed_directories` is
the Parquet folder, `enable_external_access` is off, extension auto-loading is off and
`lock_configuration` is on — so no statement can open another file or undo the lock. That
directory restriction was measured to allow *writing* inside the folder, which is why the
read-only guarantee there is the file system's: mount the folder read-only for the gateway.

### Resource protection

- Server-side statement timeout (30 s default). A client-side timeout alone leaves the
  query running on your hardware.
- Row ceiling and a 10 MB byte ceiling per result.
- A concurrency cap, so a busy agent cannot open unbounded connections to your database.
- For Parquet: a DuckDB memory ceiling (`PARQUET_MEMORY_LIMIT`, half the RAM by default),
  a thread count, a capped spill folder, one query at a time, and the statement timeout
  enforced by interrupting the query.

### Visibility

- Every statement is appended to a local JSONL audit log with the agent, user and
  conversation that triggered it, row count, duration and any error. The file is yours and
  nothing in the protocol can disable it.
- `dbStatus` on each poll lets the CMS show the data source as up or down.
- Stopping the container stops all access, immediately and unilaterally.

## What this does **not** protect against

Stated plainly, because a security control that is oversold is worse than none:

- **Data still leaves your network.** Query *results* go to Qlar and into an AI model —
  that is the entire purpose. The gateway closes the network-exposure and
  credential-storage gaps, not the data-egress one. Columns that must never leave should
  not be in the allowlist.
- **A compromised Qlar can still read what you allowed.** It could issue queries that are
  legitimate but unwelcome — reading allowed tables more broadly or more often than you
  expected. Your allowlist bounds the damage; your audit log reveals it.
- **Anyone who can read `gateway-key.pem` can impersonate this gateway** to Qlar. File
  permissions and host security are yours to maintain.
- **Anyone who can modify `.env` has your database credentials.** Same boundary as any
  application config on that host.
- **This is not a data-loss-prevention system.** It does not classify, mask or redact
  column contents.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Please do not open a public issue for a security
problem.
