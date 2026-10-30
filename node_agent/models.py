"""Strict node contract. No account, payment or user-password model belongs here."""

from datetime import datetime, timezone
from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field, AfterValidator


def instant(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.year > 2100:
        raise ValueError("Timestamp out of range")
    return value


def milliseconds(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def stamp():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


Timestamp = Annotated[
    str,
    Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"),
    AfterValidator(instant),
]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")]
OperationKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9_:.+-]{1,160}$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class Create(Model):
    external_id: Identifier
    name: str = Field(min_length=1, max_length=80, pattern=r"^[^\x00-\x1f\x7f]+$")
    expires_at: Timestamp


class Renewal(Model):
    expires_at: Timestamp
    idempotency_key: OperationKey


class Replacement(Renewal):
    expected_external_id: Identifier
    allow_create: bool = True


class Settings(Model):
    server_id: Identifier
    state_directory: str
    token_file: str
    hostname: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    endpoint_address: str = Field(pattern=r"^[0-9.]+:[0-9]+$")
    certificate_file: str
    capacity: int = Field(default=100, ge=1, le=10000)
    apply_timeout_seconds: int = Field(default=5, ge=1, le=15)


class NodeError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)
