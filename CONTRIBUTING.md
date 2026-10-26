# Contributing

Thanks for looking. This gateway runs inside other people's networks, next to their
production databases, so the bar for changes here is deliberately higher than for a
typical utility.

## Ground rules

1. **The gateway does not trust Qlar.** Any change that makes the gateway rely on Qlar
   having validated something will be declined. The guard, the read-only transaction and
   the allowlist exist precisely because the customer should not have to take Qlar's word
   for anything.
2. **Dependencies are a cost someone else pays.** Every package added here has to be
   accepted by a security review in a company you will never meet. The runtime depends on
   three libraries plus one database driver; adding a fourth needs a good argument.
3. **The protocol is a contract with software we cannot upgrade.** Gateways live on
   customer hardware and are updated on their schedule, not ours. Adding an optional field
   is fine; changing the meaning of an existing one is a protocol version bump.
4. **Comments explain why, not what.** The interesting part of this codebase is the
   reasoning — why a parser instead of a regex, why decimals become strings, why the signed
   path is relative. Preserve that.

## Getting set up

```bash
git clone https://github.com/qlar-ai/qlar-data-gateway.git
cd db-gateway
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev,all]"
pytest
ruff check .
```

`[all]` pulls all four database drivers; `[dev]` alone is enough for the unit tests, which
do not need a database.

## Tests

The suite runs without any database — the guard, crypto and encoding modules are pure
functions and a fake cursor covers the rest. Keep it that way: a test suite that needs
Oracle installed is a test suite nobody runs.

A change to `guard.py` needs tests in both directions: the thing that must be blocked, and
a piece of legitimate analytical SQL that must keep working. A guard that rejects honest
queries gets switched off, and a guard that is switched off protects nobody.

## Pull requests

- Branch from `main`; `main` itself is protected.
- One logical change per PR, with the reasoning in the description.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- `pytest` and `ruff check .` must pass; CI runs both on 3.11 and 3.12.

## Adding a database provider

Implement the `Provider` protocol in `src/qlar_data_gateway/providers/base.py` — connect,
begin a read-only transaction with a timeout, classify a driver error, and name a column
type — then register it in `providers/__init__.py`, add the extra to `pyproject.toml`, and
add the dialect and catalog schemas to `guard.py`.

`classify_error` is the part to get right: return the driver's **raw** error code. Qlar
classifies failures by code and never by message text, because message-text matching once
made plain syntax errors report as connection failures in production. A provider that
loses the code would reintroduce that bug.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
