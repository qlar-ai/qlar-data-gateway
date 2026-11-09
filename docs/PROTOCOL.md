# Qlar Data Gateway protocol, version 2

This is the complete wire contract between the on-premise gateway and Qlar. It is
published so that anyone can audit it, or write their own gateway in another language
without reading the Python.

Two rules shape everything below:

1. **The gateway only ever makes outbound requests.** Qlar never connects to the customer's
   network. There is no listening socket, no inbound firewall rule, no certificate to
   obtain, no DNS entry to publish.
2. **Both directions are signed.** HTTPS protects the channel, but on-premise deployments
   routinely terminate TLS at a proxy, so authenticity is established by signatures over
   the payloads themselves.

---

## 1. Transport

All calls are `POST`, JSON in and JSON out, to paths under the base URL the operator
configures as `QLAR_BASE_URL` (the API endpoint, ending in `/api/data-gateway` — the CMS
gateway panel prints the exact value for that deployment).

| Path | Purpose |
|---|---|
| `/enroll` | one-time registration |
| `/jobs/poll` | long-poll for work |
| `/jobs/{jobId}/result` | return the answer |

### Long polling

The gateway posts to `/jobs/poll` and Qlar holds the request open until a job appears or
`maxWaitSeconds` elapses, answering `200` with a job or `204 No Content`. Either way the
gateway immediately polls again.

`maxWaitSeconds` should stay at or below **25** — long enough that an idle gateway is not
hammering the network, short enough to sit under the 30-second idle timeout that most
corporate proxies and load balancers impose. The gateway sets its own HTTP timeout
comfortably above the server's hold so that a normal empty poll is never mistaken for a
network failure.

---

## 2. Authentication

### Keys

The gateway generates an **ECDSA P-256** key pair on first run and keeps the private key
on-premise, mode `0600`. Only the public half is ever transmitted.

P-256 with SHA-256 and DER-encoded (RFC 3279) signatures is chosen for portability: it is
available in the standard library of every runtime a port might target — Python, .NET,
Java, Node and Go — whereas Ed25519 is not (notably .NET 8 has no built-in support).

### Signing a request

Every request carries four headers:

| Header | Value |
|---|---|
| `X-Qlar-Gateway-Id` | the id Qlar issued at enrolment (absent on `/enroll`) |
| `X-Qlar-Timestamp` | Unix seconds, as a decimal string |
| `X-Qlar-Nonce` | a fresh random value, single use |
| `X-Qlar-Signature` | base64( DER( ECDSA-SHA256( canonical string ))) |
| `X-Qlar-Protocol` | `2` |

The canonical string is five fields joined by `\n`:

```
POST
/jobs/poll
1758300000
kK3f9Qx1_2bNpZr8
NdM8R3cB4yVqGfLp0sW7xK2nJ1hT6uY5a...=
```

that is:

```
METHOD \n PATH \n TIMESTAMP \n NONCE \n base64(SHA-256(body))
```

**`PATH` is the endpoint path relative to the base URL** — `/jobs/poll`, *not*
`/api/data-gateway/jobs/poll`. Qlar sits behind an API gateway that may rewrite the prefix,
and a signature that broke because of a gateway rule would be indistinguishable, from
inside the customer's network, from a wrong key.

### Verification on Qlar's side

Qlar rejects a request when the signature does not verify against the registered public
key, when the timestamp is more than **120 seconds** from its own clock, when the nonce has
been seen within the last **5 minutes**, or when the gateway is not in `active` state.

The skew window is what makes replay bounded; the nonce cache is what makes it impossible
inside that window. A clock more than two minutes out is the single most common cause of
`401` in practice — check NTP before anything else.

### Signing a job

Each job carries its own `signature` field: base64(DER(ECDSA-SHA256(canonical job bytes)))
made with **Qlar's** private key.

The canonical job bytes are **named fields in a fixed order joined by `\n`** — not
canonical JSON:

```
jobId \n type \n protocol \n sql \n maxRows \n issuedAt \n expiresAt \n agentId \n userId \n conversationId
```

A `null` or absent field contributes an empty string. Timestamps are rendered exactly as
they appear on the wire (`yyyy-MM-ddTHH:mm:ssZ`, whole seconds).

Two runtimes agreeing on "sorted keys, tight separators, no ASCII escaping" sounds simple
until a non-ASCII column name, a `/`, or a float turns up and one serializer escapes it
differently from the other — at which point every job fails verification inside a
customer's network with nothing in the logs to say why. A field list has no such
ambiguity, and it is trivial to reimplement in any language.

Everything that changes what the gateway will *do* is in that list. A field outside it is
informational only and is not covered by the signature; adding a field that affects
execution means extending the list, which is a protocol change by definition.

The gateway verifies the signature against the Qlar public key it pinned at enrolment and
silently discards a job that fails. This is what stops a proxy inside the customer's own
network from rewriting the SQL on its way in.

---

## 3. Enrolment

`POST /enroll` — the only unsigned-by-a-registered-key call, authenticated instead by a
one-time code generated in the Qlar CMS. The request is still signed, with the key being
registered, which proves the caller holds the private half rather than having copied a
public key from somewhere.

```json
{
  "enrollmentCode": "K7P4-9WQX-2MTD",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
  "fingerprint": "3A:7F:...:C2",
  "name": "warehouse-db gateway",
  "hostname": "srv-onprem-01",
  "platform": "Linux 5.15.0",
  "version": "0.1.0",
  "protocol": 1,
  "providers": ["postgresql"]
}
```

`providers` holds the one source the gateway serves: `postgresql`, `mysql`, `sqlserver`,
`oracle`, or `parquet` (a folder of Parquet files queried with DuckDB on the gateway, from
0.3.0). For `parquet` the SQL dialect is DuckDB's, an `introspect` job may read only
`information_schema`, and an `execute_query` job may name only the tables the gateway
discovered. None of this changes the wire format, so the protocol version is unchanged.

Response:

```json
{
  "gatewayId": "wrp_8fc21a...",
  "qlarPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
  "status": "pending_approval"
}
```

Enrolment codes are **single use** and expire after **15 minutes**. Qlar stores only a hash
of the code.

**Enrolment does not make the gateway usable.** It lands in `pending_approval` until a
human in the CMS compares the fingerprint shown there against the one printed by
`qlar-gateway enroll` and approves it. Without that step, whoever obtained a leaked code
could register their own machine; with it, they would also have to get an administrator to
approve a fingerprint that does not match.

---

## 4. Polling

`POST /jobs/poll`

```json
{
  "gatewayId": "wrp_8fc21a...",
  "version": "0.1.0",
  "protocol": 1,
  "dbStatus": "ok",
  "maxWaitSeconds": 25
}
```

`dbStatus` is `ok`, `unreachable` or `unknown`, and lets the CMS show the data source's
health without waiting for a user to ask a question that fails. Every poll also refreshes
the gateway's `lastSeenAt`, so polling doubles as the heartbeat — there is no separate
heartbeat call to get out of sync.

Responses:

| Status | Meaning |
|---|---|
| `200` | body contains a job (see below) |
| `204` | nothing to do; poll again immediately |
| `401` | signature, timestamp or nonce rejected |
| `403` with `{"reason":"pending_approval"}` | enrolled but not yet approved — keep polling, and say so as a wait rather than as an error |
| `403` with `{"reason":"revoked"}` | stop; a human must re-enrol this gateway |

### The job

```json
{
  "jobId": "job_01J9...",
  "type": "execute_query",
  "protocol": 1,
  "sql": "SELECT city, COUNT(*) FROM shipment_order GROUP BY city",
  "maxRows": 1000,
  "issuedAt": "2026-09-19T08:14:02Z",
  "expiresAt": "2026-09-19T08:15:02Z",
  "agentId": "agt_...",
  "userId": "usr_...",
  "conversationId": "cnv_...",
  "signature": "MEUCIQ..."
}
```

| `type` | What the gateway does |
|---|---|
| `execute_query` | run the statement, apply the table allowlist |
| `introspect` | run a catalog query; the statement may only touch catalog objects |
| `test_connection` | open a connection and report the server version |

`agentId` / `userId` / `conversationId` are carried for the **customer's** audit log. The
gateway writes them to its local JSONL file and does nothing else with them.

A job past `expiresAt` is not executed: Qlar has already stopped waiting, and running it
would spend the customer's database on an answer nobody will read.

---

## 5. Results

`POST /jobs/{jobId}/result`. Posting a result is **idempotent** — Qlar keys it by job id —
so the gateway retries on a network failure rather than discarding work the database has
already paid for.

### Success

```json
{
  "status": "ok",
  "columns": [{"name": "city", "type": "text"}, {"name": "count", "type": "int8"}],
  "rows": [["Surabaya", 128], ["Medan", 94]],
  "rowCount": 2,
  "truncated": false,
  "truncationReason": null,
  "durationMs": 83
}
```

Columnar, not one object per row: repeating column names per row is paid for twice, once
on the wire and again in tokens when the result reaches a model.

**Type rules.** JSON is lossier than a database, so:

| Source | On the wire | Why |
|---|---|---|
| `NULL` | `null` | rows are never shortened — positional rows need a fixed arity |
| integer ≤ 2^53−1 | JSON number | exactly representable as a double |
| integer > 2^53−1 | string | a JSON number would silently lose digits |
| decimal / numeric | string | same reason, and it usually holds money |
| date / time / timestamp | ISO-8601 string, offset included when present | |
| binary / blob | `"base64:<data>"` | the prefix distinguishes it from text that happens to look like base64 |
| array / JSON column | JSON array or object, encoded recursively | |
| anything else | string | a driver-specific type is better stringified than dropped |

Duplicate column names are preserved as they are. Because rows are positional they do not
collide, so no de-duplication is needed or wanted.

**Truncation.** The gateway reads one row beyond `maxRows` so that "there was more data"
can be reported instead of silently truncating, then returns at most `maxRows` with
`truncated: true` and `truncationReason: "row_limit"`. It also enforces a **byte ceiling**
(`MAX_RESULT_BYTES`, 10 MB by default) and reports `"byte_limit"` — a constraint that does
not exist on the direct path, where the result never crossed the public internet.

### Failure

```json
{
  "status": "error",
  "error": {
    "category": "sql_error",
    "driverCode": "42703",
    "messageText": "column \"revenu\" does not exist",
    "hint": "Perhaps you meant to reference the column \"revenue\".",
    "position": 23
  },
  "durationMs": 12
}
```

`driverCode` is the **raw** code: SQLSTATE for PostgreSQL, the error number for MySQL,
SQL Server and Oracle. This field is the whole reason the error envelope exists. Qlar
classifies failures by code and never by message text — message-text matching once made
plain syntax errors report as connection failures in production — and it is what lets Qlar
hand the database's own complaint back to the model for a single corrective attempt.

| `category` | Meaning | What Qlar does |
|---|---|---|
| `sql_error` | the server rejected the statement | one corrective regeneration, then report |
| `connection` | the server could not be reached or refused the login | report the data source as unavailable |
| `timeout` | cancelled for running too long | report; no retry |
| `rejected` | the **gateway** refused it before the database saw it | report as a policy violation, never retried |
| `expired` | the job was already past `expiresAt` | ignored; Qlar has moved on |

`rejected` is deliberately distinct from `sql_error`: a statement the gateway's guard
refused is not something a model can fix by rewriting the SQL, and telling it otherwise
just produces a second refusal.

---

## 6. Timeouts

Layered so that each stage gives up before the one waiting on it:

| Stage | Budget |
|---|---|
| Database statement timeout (server-side, set by the gateway) | 30 s |
| Job `expiresAt` | 60 s after issue |
| Qlar's wait for a result | 45 s |
| Dialog's HTTP call to the plugin | 100 s |

The database-side timeout is the one that matters most: a client that walks away leaves
the query running, and only a server-side limit actually stops it consuming the customer's
CPU.

---

## 7. Versioning

`X-Qlar-Protocol` and the job's `protocol` field carry the **contract** version; the
release version (`0.2.0`) moves independently. A bug-fix or feature release that does not
change the wire format must not bump the protocol.

A gateway that receives a job with a higher protocol version than it speaks refuses it
with a `rejected` error explaining that the on-premise gateway needs upgrading — rather
than guessing at a field it does not understand. Qlar keeps accepting every protocol version
it has ever published for as long as any gateway might still speak it; a fleet running inside
other people's networks cannot be upgraded on our schedule.

**Protocol 1 is the exception, and is withdrawn.** It named the caller's header
`X-Qlar-Wrapper-Id`, from before this software was called a gateway, and it was never part of
a production deployment. Qlar rejects it by name, with a message saying to upgrade, rather
than accepting the enrolment and then failing every signed request for a reason the operator
cannot see. A 0.1.x installation is not interoperable with Qlar from 0.2.0 onwards.
