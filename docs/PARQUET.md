# Parquet files

The gateway can answer from a folder of Parquet files instead of a database. It queries
them with [DuckDB](https://duckdb.org), **inside the gateway process, on your server** —
Qlar never receives the files, only the rows a question needs, exactly as with a database.

Scanning Parquet takes real CPU and memory, which is why this only exists behind the
gateway: the work happens on hardware you chose and sized, not in Qlar's cloud.

## Install

```bash
pip install "qlar-data-gateway[parquet] @ https://github.com/qlar-ai/qlar-data-gateway/releases/download/v0.3.0/qlar_data_gateway-0.3.0-py3-none-any.whl"
qlar-gateway enroll --base-url <from the CMS> --code <from the CMS>
#   Database type: parquet        (or 5)
#   Folder with the Parquet files: /data/parquet
```

Docker — the image already contains DuckDB. Mount the folder **read-only**:

```bash
echo QLAR_BASE_URL=<from the CMS> >> .env
echo QLAR_ENROLLMENT_CODE=<from the CMS> >> .env
echo DB_PROVIDER=parquet >> .env
echo PARQUET_ROOT=/data >> .env

docker run -d --name qlar-gateway --restart unless-stopped \
  --env-file .env -v "$PWD/state:/state" -v "/srv/parquet:/data:ro" \
  ghcr.io/qlar-ai/qlar-data-gateway:0.3.0 enroll
docker logs -f qlar-gateway
```

In the Qlar CMS choose **Parquet files** as the data source of the SQL Database Reader
plugin; the rest of the setup (approve the fingerprint, load the tables, describe them) is
the same as for a database.

## How files become tables

```
/srv/parquet/
  shipments/                 -> table "shipments"
    year=2025/month=10/*.parquet    partition folders become columns year, month
  vendors/vendors.parquet    -> table "vendors"     (a folder of one or more files)
  hubs.parquet               -> table "hubs"        (a file directly in the root)
  _temporary/  .cache/       ignored (names starting with _ or .)
```

- Every sub-folder of `PARQUET_ROOT` that contains `.parquet` files, at any depth, is one
  table. Files with different but compatible columns are combined by column name, so a
  column added to newer files simply reads as NULL in older ones.
- Every `.parquet` file directly in `PARQUET_ROOT` is one table.
- Names are lower-cased, and anything other than letters, digits and `_` becomes `_`
  (`Order Items` → `order_items`), so generated SQL never has to quote a table name.
- A folder that cannot be read (a corrupt file, no permission) costs only that table; the
  gateway logs it and serves the rest.

**New files** in an existing table folder are read by the very next question — the folder
is listed at query time. **New folders or new columns** appear in Qlar after
*Refresh Schema* on the plugin's Tables tab, which makes the gateway rescan.

### Optional tables file

`PARQUET_TABLES_FILE` (JSON or TOML, relative to `PARQUET_ROOT` unless absolute) renames,
adds, excludes and describes tables. Descriptions become the table and column descriptions
in Qlar's data dictionary, which the AI reads when it writes SQL.

```json
{
  "autoDiscover": true,
  "exclude": ["staging"],
  "tables": {
    "shipments": {
      "description": "One row per shipment, partitioned by year and month",
      "columns": { "cost_idr": "Shipping cost in Rupiah", "sla_days": "Promised days" }
    },
    "branches": { "path": "hubs.parquet", "description": "Branch list" },
    "returns_2025": { "path": "returns/2025/*.parquet" }
  }
}
```

A `path` is a folder, a file or a glob, and must stay inside `PARQUET_ROOT`; `..` is
refused. `"autoDiscover": false` serves only the tables listed.

There are no keys in Parquet, so Qlar sees no relations between tables. Add them as
**Virtual Foreign Keys** in the plugin's Tables tab — without them the AI has to guess how
`shipments` joins `hubs`.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `DB_PROVIDER` | — | `parquet` |
| `PARQUET_ROOT` | — | the folder (required). Nothing outside it can be read |
| `PARQUET_TABLES_FILE` | — | optional tables file, see above |
| `PARQUET_MEMORY_LIMIT` | `50%` | DuckDB memory ceiling: a share of RAM or a size (`8GB`) |
| `PARQUET_THREADS` | every core | DuckDB worker threads |
| `PARQUET_TEMP_DIR` | `duckdb-tmp` beside the state file | where a query too big for memory spills |
| `PARQUET_MAX_TEMP_SIZE` | `20GB` | ceiling on that spill folder |
| `MAX_CONCURRENT_QUERIES` | `1` | one DuckDB query already uses every thread; more only queue |
| `DB_STATEMENT_TIMEOUT_SECONDS` | `30` | a query running longer is interrupted. Qlar waits up to 80 s for a Parquet answer, so values up to about 70 are useful |
| `TABLE_ALLOWLIST` | — | narrows the tables further (names as above) |

### Sizing

DuckDB reads only the columns and row groups a query needs, and skips whole partition
folders when the question filters on them (`year = 2025`), so folder layout matters more
than raw size. As a starting point: 4 cores and 8 GB RAM answer typical aggregations over
tens of millions of rows within a few seconds. A query that needs more memory than
`PARQUET_MEMORY_LIMIT` spills to `PARQUET_TEMP_DIR`; one that still cannot finish is
reported to the user as too heavy, never retried.

## Security

The gateway decides which files exist and what each table is called; Qlar can only name
those tables. Every statement must be a single `SELECT` over them:

- table functions (`read_parquet`, `read_csv`, `glob`, `query`, …), file paths in `FROM`,
  `COPY`, `ATTACH`, `INSTALL`, `PRAGMA` and `SET` are refused before DuckDB sees them;
- DuckDB itself is locked after start-up: `allowed_directories = [PARQUET_ROOT]`,
  `enable_external_access = false`, extension auto-install/auto-load off, and
  `lock_configuration = true`, so no statement can switch any of it back.

DuckDB's directory restriction **also permits writing inside the folder**. The guard never
lets a writing statement through, but give the gateway read-only access to the files
anyway — `:ro` in Docker, or a service account without write permission. `qlar-gateway
test-db` warns when the process can write to `PARQUET_ROOT` (Linux/macOS).
