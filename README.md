# VPN node

Independent node-side control agent for VPN transports. MIT-licensed agent code;
upstream VPN implementations retain their own licenses.

**Experimental:** the first implementation manages TrustTunnel 1.1.0. This is not
a replacement for the installed Amnezia agent and is not a production release.
It has no dependency on Undercore accounts, billing, website or administrative UI.
An authenticated controller supplies an opaque external ID and an expiry time.

- [Architecture and API](docs/public/architecture.md)
- [Build and run](docs/public/running.md)

```sh
python3 -m venv .venv
.venv/bin/pip install '.[test]'
.venv/bin/python -m pytest
```

`node_agent/` owns validation, durable desired state and the HTTP API.
`runtime/managed.rs` implements a small authorization/session bridge for the
pinned official TrustTunnel endpoint. `scripts/prepare_runtime.py` applies it only
to a clean checkout of that exact revision. No client credentials or deployment
secrets belong in this repository.
