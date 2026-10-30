"""Private snapshot/ack boundary. The runtime owns expiry and session revocation."""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import time
from .models import NodeError, milliseconds


def atomic_json(path: Path, data):
    temporary = path.with_suffix(".tmp")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Runtime:
    def __init__(self, directory: Path, timeout=5):
        self.directory, self.timeout = directory, timeout

    async def apply(self, generation, rows):
        clients = []
        for row in rows:
            if row["state"] != "active":
                continue
            token = base64.b64encode((row["client_id"] + ":" + row["secret"]).encode())
            clients.append(
                dict(
                    username=row["client_id"],
                    credential=hashlib.sha256(token).hexdigest(),
                    expires_ms=milliseconds(row["expires_at"]),
                )
            )
        atomic_json(
            self.directory / "snapshot.json",
            dict(generation=generation, clients=clients),
        )
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                path = self.directory / "ack.json"
                if path.stat().st_size > 4096:
                    raise ValueError()
                ack = json.loads(path.read_bytes())
                if (
                    type(ack.get("generation")) is int
                    and ack["generation"] == generation
                    and ack.get("applied") is True
                    and isinstance(ack.get("boot"), str)
                    and type(ack.get("wall_ms")) is int
                    and 0 <= time.time() * 1000 - ack["wall_ms"] < 1000
                ):
                    return
            except (OSError, ValueError, TypeError):
                pass
            await asyncio.sleep(0.05)
        raise NodeError("runtime_unconfirmed")
