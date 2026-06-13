from __future__ import annotations

import argparse
import socket
import ssl
import sys
import uuid
from pathlib import Path
from typing import Any

from .protocol import make_message, receive_message, send_message


BASE_DIR = Path(__file__).resolve().parents[1]
CERTS_DIR = BASE_DIR / "certs"


class SecureBookingClient:
    def __init__(self, host: str, port: int, cafile: Path, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.cafile = cafile
        self.timeout = timeout
        self.sock: ssl.SSLSocket | None = None
        self.session_token: str | None = None

    def __enter__(self) -> "SecureBookingClient":
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        tcp_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock = context.wrap_socket(tcp_sock, server_hostname="localhost")
        self.sock.settimeout(self.timeout)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.sock:
            self.sock.close()

    def request(self, msg_type: str, payload: dict[str, Any] | None = None, *, token: bool = True) -> dict[str, Any]:
        if not self.sock:
            raise RuntimeError("Client is not connected")
        message = make_message(
            msg_type,
            payload or {},
            session_token=self.session_token if token else None,
        )
        send_message(self.sock, message)
        return receive_message(self.sock)

    def hello(self) -> dict[str, Any]:
        return self.request(
            "HELLO",
            {"client_name": "SecureBookingCLI", "supported_versions": ["1.0"]},
            token=False,
        )

    def auth(self, username: str, password: str) -> dict[str, Any]:
        response = self.request("AUTH", {"username": username, "password": password}, token=False)
        if response.get("type") == "AUTH_OK":
            self.session_token = response.get("session_token")
        return response

    def bye(self) -> dict[str, Any]:
        return self.request("BYE", {}, token=self.session_token is not None)


def print_response(response: dict[str, Any]) -> None:
    import json

    print(json.dumps(response, ensure_ascii=False, indent=2))


def run_authenticated(args: argparse.Namespace, operation: str, payload: dict[str, Any]) -> int:
    with SecureBookingClient(args.host, args.port, args.cafile, args.timeout) as client:
        print_response(client.hello())
        auth_response = client.auth(args.username, args.password)
        print_response(auth_response)
        if auth_response.get("type") != "AUTH_OK":
            return 1
        print_response(client.request(operation, payload))
        print_response(client.bye())
    return 0


def run_unauthorized(args: argparse.Namespace) -> int:
    with SecureBookingClient(args.host, args.port, args.cafile, args.timeout) as client:
        print_response(client.hello())
        print_response(client.request("LIST_RESOURCES", {}, token=False))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecureBooking SBP client")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=7444)
    parser.add_argument("--cafile", type=Path, default=CERTS_DIR / "ca.crt")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--username", default="student")
    parser.add_argument("--password", default="student123")

    subparsers = parser.add_subparsers(dest="command", required=True)
    resources = subparsers.add_parser("resources")
    resources.add_argument("--resource-type", choices=["room", "equipment"], default=None)
    subparsers.add_parser("bookings")
    subparsers.add_parser("ping")

    book = subparsers.add_parser("book")
    book.add_argument("--resource-id", default="ROOM-204")
    book.add_argument("--start", default="2026-06-01T08:00:00Z")
    book.add_argument("--end", default="2026-06-01T10:00:00Z")
    book.add_argument("--purpose", default="Spotkanie projektowe")
    book.add_argument("--idempotency-key", default=None)

    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("--booking-id", required=True)
    cancel.add_argument("--idempotency-key", default=None)

    subparsers.add_parser("unauthorized")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "resources":
        payload = {"resource_type": args.resource_type} if args.resource_type else {}
        code = run_authenticated(args, "LIST_RESOURCES", payload)
    elif args.command == "bookings":
        code = run_authenticated(args, "LIST_BOOKINGS", {})
    elif args.command == "ping":
        code = run_authenticated(args, "PING", {})
    elif args.command == "book":
        code = run_authenticated(
            args,
            "BOOK",
            {
                "idempotency_key": args.idempotency_key or f"IK-{uuid.uuid4()}",
                "resource_id": args.resource_id,
                "start_time": args.start,
                "end_time": args.end,
                "purpose": args.purpose,
            },
        )
    elif args.command == "cancel":
        code = run_authenticated(
            args,
            "CANCEL_BOOKING",
            {
                "idempotency_key": args.idempotency_key or f"IK-{uuid.uuid4()}",
                "booking_id": args.booking_id,
            },
        )
    else:
        code = run_unauthorized(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
