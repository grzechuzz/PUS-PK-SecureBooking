from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATABASE_FILE = DATA_DIR / "securebooking.db"
MAX_ACTIVE_BOOKINGS = 10
MIN_BOOKING_LEAD = timedelta(minutes=5)
MAX_BOOKING_DURATION = timedelta(hours=24)
MAX_BOOKING_AHEAD = timedelta(days=90)


@dataclass
class User:
    username: str
    role: str
    password_hash: str
    salt: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return digest.hex()


def create_password_record(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    return hash_password(password, salt), salt.hex()


def parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("time must use UTC Z suffix")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def validate_booking_range(start_time: str, end_time: str) -> tuple[datetime, datetime]:
    try:
        start_at = parse_utc(start_time)
        end_at = parse_utc(end_time)
    except ValueError as exc:
        raise ValueError("E_INVALID_TIME_RANGE") from exc

    now = datetime.now(timezone.utc)
    if end_at <= start_at:
        raise ValueError("E_INVALID_TIME_RANGE")
    if start_at < now + MIN_BOOKING_LEAD:
        raise ValueError("E_INVALID_TIME_RANGE")
    if end_at - start_at > MAX_BOOKING_DURATION:
        raise ValueError("E_INVALID_TIME_RANGE")
    if start_at > now + MAX_BOOKING_AHEAD:
        raise ValueError("E_INVALID_TIME_RANGE")
    return start_at, end_at


def overlaps(existing_start: str, existing_end: str, requested_start: str, requested_end: str) -> bool:
    return parse_utc(existing_start) < parse_utc(requested_end) and parse_utc(requested_start) < parse_utc(existing_end)


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


class BookingStore:
    def __init__(self, db_path: Path = DATABASE_FILE) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()
        self._seed_defaults()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS resources (
                    resource_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    building TEXT NOT NULL,
                    capacity INTEGER,
                    features_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bookings (
                    booking_id TEXT PRIMARY KEY,
                    resource_id TEXT NOT NULL REFERENCES resources(resource_id),
                    owner TEXT NOT NULL REFERENCES users(username),
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    cancelled_at TEXT
                );

                CREATE TABLE IF NOT EXISTS idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def _seed_defaults(self) -> None:
        users = [
            ("student", "student123", "user"),
            ("admin", "admin123", "admin"),
            ("grzegorz", "pus123", "user"),
            ("patryk", "pus123", "user"),
        ]
        resources = [
            ("ROOM-204", "Sala 204", "room", "B1", 24, ["projector", "whiteboard"]),
            ("ROOM-207", "Sala 207", "room", "B1", 16, ["computers"]),
            ("PROJECTOR-1", "Projektor mobilny 1", "equipment", "B1", None, ["hdmi"]),
        ]
        with self.connect() as conn:
            for username, password, role in users:
                existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
                if existing:
                    continue
                password_hash, salt = create_password_record(password)
                conn.execute(
                    "INSERT INTO users(username, role, password_hash, salt) VALUES (?, ?, ?, ?)",
                    (username, role, password_hash, salt),
                )
            for resource_id, name, resource_type, building, capacity, features in resources:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO resources(resource_id, name, type, building, capacity, features_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (resource_id, name, resource_type, building, capacity, json.dumps(features)),
                )

    def verify_user(self, username: str, password: str) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT username, role, password_hash, salt FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row:
            return None
        expected = bytes.fromhex(row["password_hash"])
        actual = bytes.fromhex(hash_password(password, bytes.fromhex(row["salt"])))
        if hmac.compare_digest(expected, actual):
            return User(row["username"], row["role"], row["password_hash"], row["salt"])
        return None

    def list_resources(self, role: str, resource_type: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT resource_id, name, type, building, capacity, features_json FROM resources"
        params: tuple[Any, ...] = ()
        if resource_type:
            query += " WHERE type = ?"
            params = (resource_type,)
        query += " ORDER BY resource_id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        resources: list[dict[str, Any]] = []
        for row in rows:
            resources.append(
                {
                    "resource_id": row["resource_id"],
                    "name": row["name"],
                    "type": row["type"],
                    "building": row["building"],
                    "capacity": row["capacity"],
                    "features": json.loads(row["features_json"]),
                }
            )
        return resources

    def list_bookings(self, username: str, role: str) -> list[dict[str, Any]]:
        query = """
            SELECT booking_id, resource_id, owner, status, start_time, end_time, purpose, created_at, cancelled_at
            FROM bookings
        """
        params: tuple[Any, ...] = ()
        if role != "admin":
            query += " WHERE owner = ?"
            params = (username,)
        query += " ORDER BY start_time, booking_id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_dict(row) for row in rows]

    def get_resource(self, conn: sqlite3.Connection, resource_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT resource_id FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()

    def create_booking(self, username: str, payload: dict[str, Any]) -> dict[str, Any]:
        resource_id = str(payload.get("resource_id", ""))
        start_time = str(payload.get("start_time", ""))
        end_time = str(payload.get("end_time", ""))
        purpose = str(payload.get("purpose", ""))

        validate_booking_range(start_time, end_time)

        with self._lock:
            with self.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if not self.get_resource(conn, resource_id):
                        raise ValueError("E_RESOURCE_NOT_FOUND")

                    active_count = conn.execute(
                        "SELECT COUNT(*) AS count FROM bookings WHERE owner = ? AND status = 'confirmed'",
                        (username,),
                    ).fetchone()["count"]
                    if active_count >= MAX_ACTIVE_BOOKINGS:
                        raise ValueError("E_BOOKING_LIMIT")

                    rows = conn.execute(
                        """
                        SELECT start_time, end_time
                        FROM bookings
                        WHERE resource_id = ? AND status = 'confirmed'
                        """,
                        (resource_id,),
                    ).fetchall()
                    for row in rows:
                        if overlaps(row["start_time"], row["end_time"], start_time, end_time):
                            raise ValueError("E_TIME_CONFLICT")

                    count = conn.execute("SELECT COUNT(*) AS count FROM bookings").fetchone()["count"]
                    booking_id = f"B-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{count + 1:04d}"
                    booking = {
                        "booking_id": booking_id,
                        "resource_id": resource_id,
                        "owner": username,
                        "status": "confirmed",
                        "start_time": start_time,
                        "end_time": end_time,
                        "purpose": purpose,
                        "created_at": utc_now(),
                        "cancelled_at": None,
                    }
                    conn.execute(
                        """
                        INSERT INTO bookings(
                            booking_id, resource_id, owner, status, start_time, end_time,
                            purpose, created_at, cancelled_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            booking["booking_id"],
                            booking["resource_id"],
                            booking["owner"],
                            booking["status"],
                            booking["start_time"],
                            booking["end_time"],
                            booking["purpose"],
                            booking["created_at"],
                            booking["cancelled_at"],
                        ),
                    )
                    conn.execute("COMMIT")
                    return booking
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

    def cancel_booking(self, username: str, role: str, booking_id: str) -> dict[str, Any]:
        with self._lock:
            with self.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    row = conn.execute(
                        """
                        SELECT booking_id, resource_id, owner, status, start_time, end_time,
                               purpose, created_at, cancelled_at
                        FROM bookings
                        WHERE booking_id = ?
                        """,
                        (booking_id,),
                    ).fetchone()
                    if not row:
                        raise ValueError("E_BOOKING_NOT_FOUND")
                    booking = row_to_dict(row)
                    if booking["owner"] != username and role != "admin":
                        raise ValueError("E_PERMISSION_DENIED")
                    if booking["status"] == "cancelled":
                        raise ValueError("E_ALREADY_CANCELLED")
                    cancelled_at = utc_now()
                    conn.execute(
                        "UPDATE bookings SET status = 'cancelled', cancelled_at = ? WHERE booking_id = ?",
                        (cancelled_at, booking_id),
                    )
                    conn.execute("COMMIT")
                    booking["status"] = "cancelled"
                    booking["cancelled_at"] = cancelled_at
                    return booking
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

    def get_idempotency(self, key: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT fingerprint, response_json FROM idempotency WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        return {"fingerprint": row["fingerprint"], "response": json.loads(row["response_json"])}

    def save_idempotency(self, key: str, fingerprint: str, response: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO idempotency(idempotency_key, fingerprint, response_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (key, fingerprint, json.dumps(response, ensure_ascii=False), utc_now()),
            )
