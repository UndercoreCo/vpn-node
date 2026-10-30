# Build and run the experimental node

Requires Linux, Python 3.10+, a Rust build environment with CMake/Clang and a
private state directory. Bind the management API to loopback during evaluation.
Do not replace an existing VPN installation. Use a dedicated listener and user.

## Endpoint source

Upstream: `https://github.com/TrustTunnel/TrustTunnel.git`.
Pinned revision: `fab5b8353a19332f935fa30869307d37d4a898d1` (1.1.0).

```sh
git clone https://github.com/TrustTunnel/TrustTunnel.git .build/trusttunnel
git -C .build/trusttunnel checkout fab5b8353a19332f935fa30869307d37d4a898d1
python3 scripts/prepare_runtime.py .build/trusttunnel
cd .build/trusttunnel
TRUSTTUNNEL_VERSION=1.1.0-node-experimental cargo test --locked -p trusttunnel authentication::managed
TRUSTTUNNEL_VERSION=1.1.0-node-experimental cargo build --locked --release -p trusttunnel_endpoint
```

The bridge changes authenticator construction and request-session cancellation;
upstream's network protocol and forwarding remain in use. Preserve upstream's
Apache-2.0 license and dependency notices in any binary distribution. Our new
bridge code is MIT. This is a modified build, not an official upstream binary.

Configure upstream `vpn.toml`, `hosts.toml` and a valid certificate as described
in its documentation. Upstream still validates a nonempty credentials file for a
public listener, but the modified endpoint authenticates exclusively from the
managed snapshot. Entries in that credentials file do not grant access.

Run endpoint as an unprivileged dedicated user with:

```sh
VPN_NODE_SNAPSHOT=/var/lib/vpn-node/snapshot.json \
VPN_NODE_ACK=/var/lib/vpn-node/ack.json \
/path/to/trusttunnel_endpoint /etc/vpn-node/vpn.toml /etc/vpn-node/hosts.toml
```

Only the dedicated service user should be able to write the state directory.
Suppress upstream traffic logs; keep process resource limits and isolate the API.
Do not grant root/Docker privileges to the HTTP agent. The runtime needs no
root privileges for a high TCP/UDP port with ICMP forwarding disabled.

## Agent settings

Create a random service token in a private file; use a secret manager or a local
secure file-writing command, never paste it into repository configuration.

```json
{
  "server_id": "example-node",
  "state_directory": "/var/lib/vpn-node",
  "token_file": "/etc/vpn-node/service.token",
  "hostname": "vpn.example.org",
  "endpoint_address": "192.0.2.10:9443",
  "certificate_file": "/etc/vpn-node/certificate.pem",
  "capacity": 100,
  "apply_timeout_seconds": 5
}
```

The example IP is documentation-only. Set explicit ingress and host egress routing
before exposing a listener; DNS does not determine the server's outbound IP.

```sh
vpn-node --settings /etc/vpn-node/agent.json --listen 127.0.0.1 --port 8795
```

For a remote controller add a trusted TLS certificate/key through `--tls-cert`
and `--tls-key`, restrict the firewall, and authenticate every request. Do not
use a TLS-verification bypass. Use systemd to manage agent/runtime independently.
A stopped agent does not remove previously accepted access before its expiry;
a stopped runtime means the tunnel is unavailable. The first authenticated API
call reconciles durable state after startup.

A fresh database intentionally starts with no access. Do not delete/reinitialize
SQLite on errors. Test grant, replay after lost response, rotation, confirmed
revoke and expiry with real client traffic before registering a node in production.

## Live lifecycle probe

`scripts/probe_lifecycle.py` uses a signature-verified official client through
isolated SOCKS listeners. Supply `--api`, `--token-file` (0600), `--binary`, its
`--sha256`, `--expected-egress`, and `--stream-url`. The stream URL must be an
operator-controlled HTTP endpoint emitting data for at least 30 seconds. This
probe creates temporary grants and disables them in cleanup; do not run it
against an unrelated node. The optional `--agent-host` explicitly allows SSH
stop/start of `undercore-trusttunnel-agent.service` on that test host to prove
expiry without the API worker. It does not collect user traffic or set local
routes. Cleanup cannot guarantee API revocation if the node is unreachable;
temporary grants additionally expire within five minutes.

Acceptance performed on 2026-10-11 with endpoint 1.1.0 plus the bridge and official
macOS CLI 1.1.11:

- HTTP/2 and HTTP/3 connect and use the configured egress IP.
- Creation replay returns the same client ID.
- Disable closes an existing TCP stream while another client's stream continues.
- Rotation replay is stable; the old password is rejected, the new one works.
- Active TCP forwarding stops at expiry with the API agent stopped.

A separate live probe also verified DNS UDP forwarding over HTTP/2 and HTTP/3,
selective UDP revocation while another client continued, and API/runtime restart
with active and revoked access preserved. The bundled lifecycle probe above
remains the TCP probe; it does not automate those additional checks.

The client must reconnect after re-enabling previously revoked access. macOS
NetworkExtension, host reboot/restore, throughput and censorship resistance
remain separate acceptance checks. Registration is limited to an explicit pilot.
