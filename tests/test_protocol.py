from __future__ import annotations

from typing import cast

from securebooking.protocol import make_message, receive_message, send_message, validate_common


class MemorySocket:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def sendall(self, data: bytes) -> None:
        self.buffer.extend(data)

    def recv(self, size: int) -> bytes:
        chunk = self.buffer[:size]
        del self.buffer[:size]
        return bytes(chunk)


def test_make_message_creates_valid_common_fields() -> None:
    message = make_message("PING", {})

    validate_common(message)

    assert message["version"] == "1.0"
    assert message["type"] == "PING"
    assert message["request_id"] is None
    assert message["session_token"] is None


def test_length_prefixed_json_roundtrip() -> None:
    sock = MemorySocket()
    message = make_message("HELLO", {"client_name": "test", "supported_versions": ["1.0"]})

    send_message(cast("object", sock), message)  # type: ignore[arg-type]
    received = receive_message(cast("object", sock))  # type: ignore[arg-type]

    assert received == message
