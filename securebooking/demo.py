from __future__ import annotations

import json
import socket
import ssl
import struct
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .client import SecureBookingClient
from .protocol import make_message, receive_message, send_message


BASE_DIR = Path(__file__).resolve().parents[1]
CERTS_DIR = BASE_DIR / "certs"


def show(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def pretty(response: dict[str, Any]) -> None:
    print(json.dumps(response, ensure_ascii=False, indent=2))


def format_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_demo_slot(hour: int) -> tuple[str, str]:
    day_offset = 7 + (uuid.uuid4().int % 60)
    start_at = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    start_at += timedelta(days=day_offset)
    end_at = start_at + timedelta(hours=2)
    return format_utc(start_at), format_utc(end_at)


def scenario_success(host: str, port: int, cafile: Path) -> tuple[str, str]:
    show("SCENARIUSZ 1: poprawna rezerwacja")
    key = f"IK-DEMO-SUCCESS-{uuid.uuid4()}"
    start_time, end_time = make_demo_slot(8)
    with SecureBookingClient(host, port, cafile) as client:
        pretty(client.hello())
        pretty(client.auth("student", "student123"))
        pretty(client.request("LIST_RESOURCES", {}))
        response = client.request(
            "BOOK",
            {
                "idempotency_key": key,
                "resource_id": "ROOM-204",
                "start_time": start_time,
                "end_time": end_time,
                "purpose": "Demo poprawnej rezerwacji",
            },
        )
        pretty(response)
        pretty(client.request("LIST_BOOKINGS", {}))
        pretty(client.bye())
    conflict_start = format_utc(datetime.fromisoformat(start_time[:-1] + "+00:00") + timedelta(hours=1))
    conflict_end = format_utc(datetime.fromisoformat(end_time[:-1] + "+00:00") + timedelta(hours=1))
    return conflict_start, conflict_end


def scenario_conflict(host: str, port: int, cafile: Path, start_time: str, end_time: str) -> None:
    show("SCENARIUSZ 2: blad - konflikt terminu")
    with SecureBookingClient(host, port, cafile) as client:
        pretty(client.hello())
        pretty(client.auth("patryk", "pus123"))
        response = client.request(
            "BOOK",
            {
                "idempotency_key": f"IK-DEMO-CONFLICT-{uuid.uuid4()}",
                "resource_id": "ROOM-204",
                "start_time": start_time,
                "end_time": end_time,
                "purpose": "Demo konfliktu",
            },
        )
        pretty(response)
        pretty(client.bye())


def scenario_unauthorized(host: str, port: int, cafile: Path) -> None:
    show("SCENARIUSZ 3: bezpieczenstwo - operacja bez AUTH")
    with SecureBookingClient(host, port, cafile) as client:
        pretty(client.hello())
        pretty(client.request("LIST_RESOURCES", {}, token=False))


def scenario_idempotency(host: str, port: int, cafile: Path) -> None:
    show("SCENARIUSZ 4: awaria/retry - ten sam idempotency_key")
    key = f"IK-DEMO-RETRY-{uuid.uuid4()}"
    start_time, end_time = make_demo_slot(12)
    payload = {
        "idempotency_key": key,
        "resource_id": "ROOM-207",
        "start_time": start_time,
        "end_time": end_time,
        "purpose": "Demo retry",
    }
    with SecureBookingClient(host, port, cafile) as client:
        pretty(client.hello())
        pretty(client.auth("student", "student123"))
        first = client.request("BOOK", payload)
        pretty(first)
        second = client.request("BOOK", payload)
        pretty(second)
        pretty(client.bye())


def scenario_bad_json(host: str, port: int, cafile: Path) -> None:
    show("SCENARIUSZ 5: blad - niepoprawny JSON")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            hello = make_message(
                "HELLO",
                {"client_name": "BrokenClient", "supported_versions": ["1.0"]},
                session_token=None,
            )
            send_message(tls, hello)
            pretty(receive_message(tls))
            bad = b'{"version":"1.0","type":'
            tls.sendall(struct.pack(">I", len(bad)) + bad)
            pretty(receive_message(tls))


def main() -> None:
    host = "localhost"
    port = 7444
    cafile = CERTS_DIR / "ca.crt"
    conflict_start, conflict_end = scenario_success(host, port, cafile)
    scenario_conflict(host, port, cafile, conflict_start, conflict_end)
    scenario_unauthorized(host, port, cafile)
    scenario_idempotency(host, port, cafile)
    scenario_bad_json(host, port, cafile)


if __name__ == "__main__":
    main()
