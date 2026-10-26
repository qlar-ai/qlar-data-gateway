# Releasing

How a version of the gateway is cut and published. The deployment runbook for the Qlar
side lives in the `Plugins-pack` repository
(`docs/db-gateway-deployment-runbook.md`); this page covers only this repository.

## The ordering rule

**Qlar is released first; the gateway follows.**

The gateway is a client of Qlar's protocol. A gateway published before the matching Qlar
release would enrol against endpoints that do not exist yet, and the first thing a
customer would see is a failure. Qlar's side is backward compatible by design — existing
direct-mode configurations keep working untouched — so releasing it early costs nothing.

Never publish a gateway release whose protocol version Qlar production does not yet
accept.

## Version numbers

Two of them, deliberately independent:

- **Release version** (`0.1.0`) — lives in `src/qlar_data_gateway/__init__.py` as
  `__version__`, and `pyproject.toml` reads it from there. That is the only place to edit.
- **Protocol version** (`PROTOCOL_VERSION`, currently `1`) — the wire contract. A bug fix
  or a new command does **not** bump it. Only an incompatible change to the protocol does,
  and that needs a migration plan, because the fleet runs inside customer networks and
  upgrades on their schedule, not ours.

Semantic versioning applies to the release number. Before 1.0, a breaking change bumps the
minor.

## Checklist

1. **Changelog.** Move the `## [Unreleased]` entries under a new `## [x.y.z] - YYYY-MM-DD`
   heading, and update the link definitions at the bottom.
2. **Version.** Edit `__version__` in `src/qlar_data_gateway/__init__.py`.
3. **Verify locally.**
   ```bash
   pytest -q
   ruff check .
   python -m build
   docker build -t qlar-gateway:rc .
   ```
4. **PR into `main`** with those changes. `main` is protected; the release commit goes
   through review like anything else.
5. **Confirm the Qlar side is live in production** and accepts this protocol version.
6. **Tag and push.**
   ```bash
   git checkout main && git pull
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

The `Release` workflow then refuses to proceed if the tag and `__version__` disagree,
builds the sdist and wheel, writes SHA-256 checksums, builds and pushes
`ghcr.io/qlar-ai/qlar-data-gateway:<version>` and `:latest`, and creates the GitHub Release with
the artifacts attached.

7. **Verify the published artifacts** the way a customer would:
   ```bash
   docker pull ghcr.io/qlar-ai/qlar-data-gateway:0.1.0
   docker run --rm ghcr.io/qlar-ai/qlar-data-gateway:0.1.0 version
   sha256sum -c qlar_data_gateway-0.1.0.sha256
   ```
8. **Point the CMS download page at the new release** and check that the version it
   advertises matches.

## After a release

Customers upgrade on their own schedule, so treat every published version as permanently
deployed somewhere. In practice that means:

- Qlar keeps accepting older protocol versions for as long as any gateway might still
  speak them.
- A security fix warrants a note on the release and, for anything serious, contacting
  customers directly rather than waiting for them to notice a tag.
- Never delete or re-point a published tag. Someone's deployment pins it.
