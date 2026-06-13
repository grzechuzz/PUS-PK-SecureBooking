from __future__ import annotations

import argparse
import hashlib
import secrets
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .protocol import (
    ProtocolError,
    make_error,
    make_message,
    make_ok,
    receive_message,
    send_message,
    stable_payload_for_idempotency,
    validate_common,
)
from .store import BookingStore, User


BASE_DIR = Path(__file__).resolve().parents[1]
CERTS_DIR = BASE_DIR / "certs"
SESSION_TTL = timedelta(minutes=30)
SOCKET_TIMEOUT = 5.0
AUTH_RATE_WINDOW = timedelta(minutes=1)
MAX_FAILED_AUTH_PER_WINDOW = 5
MAX_ACTIVE_SESSIONS_PER_USER = 3


ERROR_MESSAGES = {
    "E_RESOURCE_NOT_FOUND": "Resource does not exist",
    "E_INVALID_TIME_RANGE": "Invalid booking time range",
    "E_TIME_CONFLICT": "Resource is already booked in selected time range",
    "E_BOOKING_LIMIT": "User exceeded active booking limit",
    "E_PERMISSION_DENIED": "Permission denied",
    "E_ALREADY_CANCELLED": "Booking is already cancelled",
    "E_BOOKING_NOT_FOUND": "Booking does not exist",
    "E_IDEMPOTENCY_CONFLICT": "idempotency_key was reused with different payload",
    "E_SESSION_LIMIT": "User has too many active sessions",
    "E_RATE_LIMIT": "Too many authentication attempts",
}


@dataclass
class Session:
    username: str
    role: str
    expires_at: datetime


class SecureBookingServer:
    def __init__(self, host: str, port: int, certfile: Path, keyfile: Path) -> None:
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.store = BookingStore()
        self.sessions: dict[str, Session] = {}
        self.auth_failures: dict[str, list[datetime]] = {}
        self.seen_messages: dict[str, str] = {}
        self.lock = threading.RLock()

    def build_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        return context

    def serve_forever(self) -> None:
        context = self.build_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(20)
            print(f"[SERVER] SecureBooking listening on {self.host}:{self.port}")
            print(f"[SERVER] Certificate: {self.certfile}")
            try:
                while True:
                    client, address = server_socket.accept()
                    thread = threading.Thread(
                        target=self.handle_tcp_client,
                        args=(context, client, address),
                        daemon=True,
                    )
                    thread.start()
            except KeyboardInterrupt:
                print("\n[SERVER] Stopped.")

    def handle_tcp_client(
        self,
        context: ssl.SSLContext,
        client: socket.socket,
        address: tuple[str, int],
    ) -> None:
        try:
            with context.wrap_socket(client, server_side=True) as tls_socket:
                tls_socket.settimeout(SOCKET_TIMEOUT)
                print(f"[SERVER] TLS connection from {address}, version={tls_socket.version()}")
                self.handle_protocol_session(tls_socket)
        except ssl.SSLError as exc:
            print(f"[SERVER] TLS error from {address}: {exc}")
        except OSError as exc:
            print(f"[SERVER] Connection closed for {address}: {exc}")
        finally:
            client.close()

    def handle_protocol_session(self, sock: ssl.SSLSocket) -> None:
        negotiated = False
        authenticated = False
        syntax_errors = 0

        while True:
            message = None
            try:
                message = receive_message(sock)
                self.check_duplicate_message(message)
                msg_type = message.get("type")

                if msg_type == "HELLO":
                    validate_common(message)
                    response = make_message(
                        "HELLO_OK",
                        {
                            "selected_version": "1.0",
                            "max_frame_size": 65536,
                            "server_time": datetime.now(timezone.utc)
                            .replace(microsecond=0)
                            .isoformat()
                            .replace("+00:00", "Z"),
                        },
                        request_id=message["message_id"],
                    )
                    send_message(sock, response)
                    negotiated = True
                    continue

                if not negotiated:
                    raise ProtocolError("E_UNEXPECTED_MESSAGE", "HELLO is required before other messages")

                if msg_type == "AUTH":
                    validate_common(message)
                    response = self.handle_auth(message)
                    send_message(sock, response)
                    authenticated = response.get("type") == "AUTH_OK"
                    continue

                if msg_type == "PING":
                    validate_common(message)
                    send_message(sock, make_message("PONG", {}, request_id=message["message_id"]))
                    continue

                if msg_type == "BYE":
                    validate_common(message, require_token=authenticated)
                    if authenticated:
                        self.require_session(message["session_token"])
                        self.close_session(message["session_token"])
                    send_message(sock, make_message("BYE", {}, request_id=message["message_id"]))
                    break

                if not authenticated:
                    raise ProtocolError("E_AUTH_REQUIRED", "AUTH is required before this operation", retryable=True)

                validate_common(message, require_token=True)
                session = self.require_session(message["session_token"])
                response = self.dispatch_authenticated(message, session)
                send_message(sock, response)

            except ProtocolError as exc:
                syntax_errors += 1 if exc.code in {"E_BAD_FRAME", "E_BAD_JSON", "E_SCHEMA"} else 0
                send_message(sock, make_error(message, exc.code, exc.message, retryable=exc.retryable))
                if syntax_errors >= 3 or exc.code in {"E_BAD_FRAME"}:
                    break
            except socket.timeout:
                send_message(sock, make_error(message, "E_TIMEOUT", "Timeout while reading message"))
                break

    def check_duplicate_message(self, message: dict[str, Any]) -> None:
        message_id = str(message.get("message_id", ""))
        digest = hashlib.sha256(repr(message).encode("utf-8")).hexdigest()
        with self.lock:
            previous = self.seen_messages.get(message_id)
            if previous and previous != digest:
                raise ProtocolError("E_REPLAY_DETECTED", "message_id reused with different content")
            self.seen_messages[message_id] = digest

    def handle_auth(self, message: dict[str, Any]) -> dict[str, Any]:
        payload = message["payload"]
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if self.is_auth_rate_limited(username):
            return make_message(
                "AUTH_FAIL",
                {"code": "E_RATE_LIMIT", "message": "Authentication temporarily limited", "retryable": True},
                request_id=message["message_id"],
            )

        user = self.store.verify_user(username, password)
        if not user:
            self.register_auth_failure(username)
            return make_message(
                "AUTH_FAIL",
                {"code": "E_AUTH_FAILED", "message": "Authentication failed", "retryable": True},
                request_id=message["message_id"],
            )
        self.clear_auth_failures(username)
        token = self.create_session(user)
        return make_message(
            "AUTH_OK",
            {"expires_in": int(SESSION_TTL.total_seconds()), "role": user.role},
            request_id=message["message_id"],
            session_token=token,
        )

    def is_auth_rate_limited(self, username: str) -> bool:
        now = datetime.now(timezone.utc)
        with self.lock:
            failures = [
                failed_at for failed_at in self.auth_failures.get(username, []) if now - failed_at <= AUTH_RATE_WINDOW
            ]
            self.auth_failures[username] = failures
            return len(failures) >= MAX_FAILED_AUTH_PER_WINDOW

    def register_auth_failure(self, username: str) -> None:
        now = datetime.now(timezone.utc)
        with self.lock:
            failures = [
                failed_at for failed_at in self.auth_failures.get(username, []) if now - failed_at <= AUTH_RATE_WINDOW
            ]
            failures.append(now)
            self.auth_failures[username] = failures

    def clear_auth_failures(self, username: str) -> None:
        with self.lock:
            self.auth_failures.pop(username, None)

    def create_session(self, user: User) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            now = datetime.now(timezone.utc)
            self.sessions = {
                session_token: session for session_token, session in self.sessions.items() if session.expires_at >= now
            }
            active_sessions = sum(1 for session in self.sessions.values() if session.username == user.username)
            if active_sessions >= MAX_ACTIVE_SESSIONS_PER_USER:
                raise ProtocolError("E_SESSION_LIMIT", ERROR_MESSAGES["E_SESSION_LIMIT"])
            self.sessions[token] = Session(
                username=user.username,
                role=user.role,
                expires_at=now + SESSION_TTL,
            )
        return token

    def require_session(self, token: str) -> Session:
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                raise ProtocolError("E_AUTH_REQUIRED", "Unknown session token", retryable=True)
            if session.expires_at < datetime.now(timezone.utc):
                del self.sessions[token]
                raise ProtocolError("E_SESSION_EXPIRED", "Session expired", retryable=True)
            session.expires_at = datetime.now(timezone.utc) + SESSION_TTL
            return session

    def close_session(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    def dispatch_authenticated(self, message: dict[str, Any], session: Session) -> dict[str, Any]:
        msg_type = message["type"]
        if msg_type == "LIST_RESOURCES":
            resource_type = message["payload"].get("resource_type")
            if resource_type is not None and not isinstance(resource_type, str):
                raise ProtocolError("E_SCHEMA", "resource_type must be string or null")
            return make_ok(
                message,
                {"operation": "LIST_RESOURCES", "resources": self.store.list_resources(session.role, resource_type)},
            )
        if msg_type == "LIST_BOOKINGS":
            return make_ok(
                message,
                {
                    "operation": "LIST_BOOKINGS",
                    "bookings": self.store.list_bookings(session.username, session.role),
                },
            )
        if msg_type in {"BOOK", "CANCEL_BOOKING"}:
            return self.handle_idempotent_operation(message, session)
        raise ProtocolError("E_UNEXPECTED_MESSAGE", f"Unsupported authenticated message: {msg_type}")

    def handle_idempotent_operation(self, message: dict[str, Any], session: Session) -> dict[str, Any]:
        payload = message["payload"]
        idempotency_key = payload.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ProtocolError("E_SCHEMA", "idempotency_key is required")

        fingerprint = stable_payload_for_idempotency(message, session.username)
        with self.lock:
            previous = self.store.get_idempotency(idempotency_key)
        if previous:
            if previous["fingerprint"] != fingerprint:
                raise ProtocolError("E_IDEMPOTENCY_CONFLICT", ERROR_MESSAGES["E_IDEMPOTENCY_CONFLICT"])
            return previous["response"]

        try:
            if message["type"] == "BOOK":
                booking = self.store.create_booking(session.username, payload)
                response = make_ok(
                    message,
                    {
                        "operation": "BOOK",
                        "booking_id": booking["booking_id"],
                        "resource_id": booking["resource_id"],
                        "status": booking["status"],
                        "start_time": booking["start_time"],
                        "end_time": booking["end_time"],
                    },
                )
            else:
                booking_id = str(payload.get("booking_id", ""))
                booking = self.store.cancel_booking(session.username, session.role, booking_id)
                response = make_ok(
                    message,
                    {
                        "operation": "CANCEL_BOOKING",
                        "booking_id": booking["booking_id"],
                        "status": booking["status"],
                    },
                )
        except ValueError as exc:
            code = str(exc)
            response = make_error(message, code, ERROR_MESSAGES.get(code, code), retryable=code == "E_TIME_CONFLICT")

        with self.lock:
            self.store.save_idempotency(idempotency_key, fingerprint, response)
        return response


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecureBooking SBP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7444)
    parser.add_argument("--certfile", type=Path, default=CERTS_DIR / "server.crt")
    parser.add_argument("--keyfile", type=Path, default=CERTS_DIR / "server.key")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = SecureBookingServer(args.host, args.port, args.certfile, args.keyfile)
    server.serve_forever()


if __name__ == "__main__":
    main()
