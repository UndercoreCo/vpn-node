"""Durable intentions precede runtime changes; retries retain keys and remote identity."""

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from .models import NodeError, milliseconds, stamp

FIELDS = ("client_id", "external_id", "name", "expires_at", "created_at", "updated_at")


class Store:
    def __init__(self, directory, capacity):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        self.path = directory / "node.sqlite3"
        self.capacity = capacity
        if not self.path.exists():
            self.path.touch(mode=0o600)
        os.chmod(self.path, 0o600)
        with self.connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise NodeError("unsupported_schema")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY, external_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL, expires_at TEXT NOT NULL, creation_expiry TEXT NOT NULL,
                    state TEXT NOT NULL, secret TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operations (
                    client_id TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    PRIMARY KEY(client_id, key));
                CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL);
                INSERT OR IGNORE INTO metadata VALUES (1, 1);
                PRAGMA user_version=1;
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def changed(db):
        db.execute("UPDATE metadata SET generation=generation+1 WHERE id=1")

    def snapshot(self):
        with self.connect() as db:
            db.execute("BEGIN")
            generation = db.execute(
                "SELECT generation FROM metadata WHERE id=1"
            ).fetchone()[0]
            return generation, [
                dict(row)
                for row in db.execute("SELECT * FROM clients ORDER BY client_id")
            ]

    def row(self, client_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM clients WHERE client_id=?", (client_id,)
            ).fetchone()
            if row is None:
                raise NodeError("not_found", 404)
            return dict(row)

    @staticmethod
    def view(row):
        status = row["state"]
        if milliseconds(row["expires_at"]) <= time.time() * 1000:
            status = "expired"
        return {**{key: row[key] for key in FIELDS}, "status": status}

    def create(self, body):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT * FROM clients WHERE external_id=?", (body.external_id,)
            ).fetchone()
            if prior is not None:
                if prior["creation_expiry"] != body.expires_at:
                    raise NodeError("creation_lifetime_conflict", 409)
                return prior["client_id"]
            if milliseconds(body.expires_at) <= time.time() * 1000:
                raise NodeError("grant_expired", 410)
            if (
                db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
                >= self.capacity
            ):
                raise NodeError("capacity_exhausted", 409)
            client_id, now = "ttapi_" + secrets.token_hex(16), stamp()
            db.execute(
                "INSERT INTO clients VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    client_id,
                    body.external_id,
                    body.name,
                    body.expires_at,
                    body.expires_at,
                    "active",
                    secrets.token_urlsafe(32),
                    now,
                    now,
                ),
            )
            self.changed(db)
            return client_id

    def mutate(self, client_id, operation, payload):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute(
                "SELECT * FROM clients WHERE client_id=?", (client_id,)
            ).fetchone()
            if result is None:
                raise NodeError("not_found", 404)
            row = dict(result)
            key = payload.get("idempotency_key")
            fingerprint = hashlib.sha256(
                json.dumps([operation, payload], sort_keys=True).encode()
            ).hexdigest()
            if key:
                old = db.execute(
                    "SELECT fingerprint FROM operations WHERE client_id=? AND key=?",
                    (client_id, key),
                ).fetchone()
                if old:
                    if old[0] != fingerprint:
                        raise NodeError("operation_conflict", 409)
                    # Return current state, never replay an old enable/rotation after revoke.
                    return
            if operation == "disable":
                row["state"] = "disabled"
            elif operation == "enable":
                if milliseconds(row["expires_at"]) <= time.time() * 1000:
                    raise NodeError("grant_expired", 410)
                row["state"] = "active"
            elif operation in ("renew", "replace"):
                if milliseconds(payload["expires_at"]) <= time.time() * 1000:
                    raise NodeError("grant_expired", 410)
                if operation == "replace":
                    if row["external_id"] != payload["expected_external_id"]:
                        raise NodeError("identity_conflict", 409)
                    if (
                        not payload["allow_create"]
                        and self.view(row)["status"] != "active"
                    ):
                        raise NodeError("access_unavailable", 409)
                    row["secret"] = secrets.token_urlsafe(32)
                    row["state"] = "active"
                row["expires_at"] = payload["expires_at"]
            else:
                raise NodeError("unsupported_operation", 422)
            row["updated_at"] = stamp()
            db.execute(
                "UPDATE clients SET state=?,secret=?,expires_at=?,updated_at=? WHERE client_id=?",
                (
                    row["state"],
                    row["secret"],
                    row["expires_at"],
                    row["updated_at"],
                    client_id,
                ),
            )
            if key:
                db.execute(
                    "INSERT INTO operations VALUES (?,?,?)",
                    (client_id, key, fingerprint),
                )
            self.changed(db)
