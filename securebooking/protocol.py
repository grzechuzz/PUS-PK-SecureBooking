from __future__ import annotations

import json
import socket
import struct
import uuid
from datetime import datetime, timezone
from typing import Any

from . import PROTOCOL_VERSION


MAX_FRAME_SIZE = 64 * 1024
TIMESTAMP_SKEW_SECONDS = 120


class ProtocolError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_message_id() -> str:
    return str(uuid.uuid4())


def make_message(
    msg_type: str,
    payload: dict[str, Any] | None = None,
    *,
    request_id: str | None = None,
    session_token: str | None = None,
) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "type": msg_type,
        "message_id": new_message_id(),
        "request_id": request_id,
        "session_token": session_token,
        "timestamp": utc_now(),
        "payload": payload or {},
    }


def make_ok(
    request: dict[str, Any],
    payload: dict[str, Any],
    *,
    session_token: str | None = None,
) -> dict[str, Any]:
    return make_message(
        "OK",
        payload,
        request_id=request.get("message_id"),
        session_token=session_token,
    )


def make_error(
    request: dict[str, Any] | None,
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> dict[str, Any]:
    return make_message(
        "ERROR",
        {"code": code, "message": message, "retryable": retryable},
        request_id=request.get("message_id") if request else None,
        session_token=None,
    )


def send_message(sock: socket.socket, message: dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError("E_BAD_FRAME", "Frame is too large")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("E_TIMEOUT", "Connection closed while reading frame", retryable=True)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(sock: socket.socket) -> dict[str, Any]:
    header = read_exact(sock, 4)
    frame_size = struct.unpack(">I", header)[0]
    if frame_size > MAX_FRAME_SIZE:
        raise ProtocolError("E_BAD_FRAME", "Frame exceeds max_frame_size")
    raw = read_exact(sock, frame_size)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("E_BAD_FRAME", "Frame is not valid UTF-8") from exc
    try:
        message = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ProtocolError("E_BAD_JSON", "Frame payload is not valid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("E_SCHEMA", "Message root must be an object")
    return message


def parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z suffix")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def validate_common(message: dict[str, Any], *, require_token: bool = False) -> None:
    required = ("version", "type", "message_id", "request_id", "session_token", "timestamp", "payload")
    for field in required:
        if field not in message:
            raise ProtocolError("E_SCHEMA", f"Missing field: {field}")

    if message["version"] != PROTOCOL_VERSION:
        raise ProtocolError("E_VERSION_UNSUPPORTED", "Unsupported protocol version")
    if not isinstance(message["type"], str):
        raise ProtocolError("E_SCHEMA", "type must be string")
    try:
        uuid.UUID(str(message["message_id"]))
    except ValueError as exc:
        raise ProtocolError("E_SCHEMA", "message_id must be UUID") from exc
    if message["request_id"] is not None:
        try:
            uuid.UUID(str(message["request_id"]))
        except ValueError as exc:
            raise ProtocolError("E_SCHEMA", "request_id must be UUID or null") from exc
    if require_token and not isinstance(message["session_token"], str):
        raise ProtocolError("E_AUTH_REQUIRED", "session_token is required")
    if not isinstance(message["payload"], dict):
        raise ProtocolError("E_SCHEMA", "payload must be object")
    try:
        timestamp = parse_timestamp(str(message["timestamp"]))
    except ValueError as exc:
        raise ProtocolError("E_SCHEMA", "timestamp must be ISO-8601 UTC") from exc
    skew = abs((datetime.now(timezone.utc) - timestamp).total_seconds())
    if skew > TIMESTAMP_SKEW_SECONDS:
        raise ProtocolError("E_TIMEOUT", "timestamp differs from server time by more than 120 seconds")


def stable_payload_for_idempotency(message: dict[str, Any], username: str) -> str:
    payload = {
        "type": message["type"],
        "username": username,
        "payload": message["payload"],
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
