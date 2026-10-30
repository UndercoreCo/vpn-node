# Architecture and contract

The controller decides whether access is authorized. This agent knows only an
opaque `external_id`, a display name and an absolute UTC expiry. It does not
validate payments, email addresses, subscriptions or available device slots.

## Components

- `models.py`: strict input/settings models and safe error codes.
- `store.py`: SQLite intentions, stable client identity and durable operation keys.
- `runtime.py`: atomic desired snapshot and bounded acknowledgement wait.
- `api.py`: authenticated API, serialized mutations, secret connection export.
- `main.py`: launch configuration, TLS and one-worker server policy.
- `runtime/managed.rs`: dynamic authenticator and cancellable per-request permits
  inside upstream TrustTunnel. It is not a new packet-forwarding implementation.

The private state directory contains `node.sqlite3`, `snapshot.json`, and
`ack.json`. SQLite contains passwords; snapshots contain credential hashes.
Both are sensitive. Permissions are 0700/0600. Back up the entire state as a
coherent unit while stopped. Replacing it with an older backup while the endpoint
is running is unsupported: stale state must never reactivate revoked access.

A mutation commits its intent before applying a snapshot. A 503 is ambiguous,
not proof of failure. Repeat the same creation external ID or operation key.
Success requires a fresh acknowledgement of that exact generation. Revocation
also waits for affected forwarding futures to release their permits. Existing
unaffected sessions remain active. Expiry is checked by authentication and by
each live permit, independent of the HTTP agent. Expired credentials cannot
start a new stream. Removing a permit closes data forwarding; an idle outer
HTTP/2 or QUIC connection may remain until upstream's normal timeout.

The runtime rejects decreasing snapshot generations, malformed snapshots and
large backwards clock jumps. Invalid state fails closed. Wall and monotonic
time both bound live permits. A process restart cannot resume old in-memory
sessions. Restoring the complete machine/clock to an old snapshot still requires
operator reconciliation; this prototype is not an anti-rollback hardware system.

## API v1

All endpoints require `Authorization: Bearer …`; use TLS outside loopback.
Responses, including errors, carry `Cache-Control: private, no-store`.
Input bodies are bounded to 16 KiB. Unknown fields and invalid types are rejected.
Identifiers are opaque ASCII strings. Timestamps use `YYYY-MM-DDTHH:mm:ss.sssZ`.
Never log request/response bodies or put the service token in a command argument.

| Method and path | Input / result |
|---|---|
| GET `/v1/health` | Identity and runtime-confirmed lifecycle capabilities |
| GET `/v1/clients` | Complete inventory, including disabled/expired identities |
| POST `/v1/clients` | `external_id`, `name`, `expires_at`; idempotent identity |
| GET `/v1/clients/{id}` | Current runtime-confirmed metadata |
| GET `/v1/clients/{id}/connection` | Active metadata and private `endpoint_export` TOML |
| POST `/v1/clients/{id}/renew` | `expires_at`, `idempotency_key`; same credentials |
| POST `/v1/clients/{id}/replace` | Plus `expected_external_id`, `allow_create`; rotate password |
| POST `/v1/clients/{id}/disable` | `{}`; confirmed closure of that client's forwarding |
| POST `/v1/clients/{id}/enable` | `{}`; rejects expired grants |

Successful envelopes contain `schema_version=1`, `server_id`,
`protocol=trusttunnel`, `status=ok`. A client result includes `applied=true` and
`client` metadata. The export includes a public TLS certificate, username,
password, endpoint address and supported transport. It never disables TLS
verification. Orchestrator adapters convert this into their transport manifest;
client applications supply their own listener/routing policy.

| HTTP | Meaning |
|---|---|
| 401 | Missing/invalid controller credential |
| 404 | Unknown remote identity |
| 409 | Identity, idempotency, creation lifetime or capacity conflict |
| 410 | Expired/unavailable access |
| 413 | Request exceeds the body limit |
| 422 | Unsupported operation or invalid input |
| 503 | Runtime application unconfirmed or node unavailable; repeat safely |

Errors contain only `detail` with a stable safe code. They never include upstream
exceptions, credentials, configuration lines or traffic destinations.

## Current limits

Single HTTP worker, one runtime, IPv4 node egress, maximum 10,000 journal entries.
Disabled identities are retained and count toward the configured journal capacity.
No delete/garbage collection, packaged installer, public release, metrics UI or
automatic database-backup restoration yet. Service TLS/token rotation is an
operator operation. Read-only metadata currently waits for runtime confirmation.
Do not infer production readiness from passing unit tests alone: real session
revocation, expiry, agent/runtime restart and NetworkExtension acceptance matter.
