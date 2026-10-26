# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Email **security@pusaka.ai** with:

- what the problem is and which component it affects,
- the version (`qlar-gateway version`) and how it is deployed,
- the smallest reproduction you can manage.

You will get an acknowledgement within **2 business days** and an assessment with a fix
timeline within **10 business days**. We will keep you updated while a fix is prepared,
credit you in the release notes unless you prefer otherwise, and coordinate disclosure
timing with you.

Please do not include real credentials, connection strings, `.env` contents or private
keys in your report — a redacted description is always enough to start.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

While the project is pre-1.0, security fixes go to the latest minor release only.

## Scope

In scope: anything that lets a caller run SQL the gateway should have refused, read data
outside a configured allowlist, impersonate a gateway or Qlar, bypass signature or replay
protection, or extract the private key or database credentials from the process.

Out of scope, because they are documented properties rather than defects (see
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)): query results being sent to Qlar and
into an AI model, which is the purpose of the software; an attacker who already has read
access to `gateway-key.pem` or `.env` on the host; and the gateway being unable to protect
a database account that was granted write permissions against the operator's own choice.

## Verifying a release

Every release publishes SHA-256 checksums alongside the artifacts. Check them before
installing:

```bash
sha256sum -c qlar_data_gateway-0.1.6.sha256
```

Docker images are published to `ghcr.io/qlar-ai/qlar-data-gateway` and can be pinned by digest.
