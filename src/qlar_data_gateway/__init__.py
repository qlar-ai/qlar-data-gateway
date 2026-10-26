"""Qlar Data Gateway — on-premise SQL access gateway.

The gateway runs inside the customer's network, pulls SQL jobs from Qlar over an
outbound HTTPS connection, executes them read-only against a local database, and posts
the results back. No inbound port is opened, and the database credentials never leave
the customer's premises.
"""

# Single source of truth for the release version: pyproject.toml reads it from here
# (`[tool.setuptools.dynamic] version = { attr = "qlar_data_gateway.__version__" }`), so a
# release only ever has to change this line plus CHANGELOG.md.
__version__ = "0.2.1"

# The wire contract version, deliberately separate from the release version. Qlar sends it
# back in every job and rejects a gateway that speaks a version it does not support, so a
# bug-fix release must NOT bump this — only an incompatible protocol change does.
PROTOCOL_VERSION = 2

__all__ = ["__version__", "PROTOCOL_VERSION"]
