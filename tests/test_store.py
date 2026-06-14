from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from securebooking.store import BookingStore


@pytest.fixture
def store(tmp_path: Path) -> BookingStore:
    return BookingStore(tmp_path / "securebooking-test.db")


def format_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def future_slot(days: int = 14, hour: int = 8, duration_hours: int = 2) -> tuple[str, str]:
    start_at = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    start_at += timedelta(days=days)
    end_at = start_at + timedelta(hours=duration_hours)
    return format_utc(start_at), format_utc(end_at)


def test_seeded_user_can_be_verified(store: BookingStore) -> None:
    user = store.verify_user("student", "student123")

    assert user is not None
    assert user.username == "student"
    assert user.role == "user"


def test_password_is_rejected_when_invalid(store: BookingStore) -> None:
    user = store.verify_user("student", "wrong-password")

    assert user is None


def test_list_resources_can_filter_by_type(store: BookingStore) -> None:
    rooms = store.list_resources("user", "room")

    assert rooms
    assert all(resource["type"] == "room" for resource in rooms)


def test_booking_conflict_is_rejected_atomically(store: BookingStore) -> None:
    start_time, end_time = future_slot(days=14, hour=8)
    overlap_start, overlap_end = future_slot(days=14, hour=9)
    payload = {
        "resource_id": "ROOM-204",
        "start_time": start_time,
        "end_time": end_time,
        "purpose": "Test booking",
    }
    created = store.create_booking("student", payload)

    assert created["status"] == "confirmed"

    with pytest.raises(ValueError, match="E_TIME_CONFLICT"):
        store.create_booking(
            "patryk",
                {
                    "resource_id": "ROOM-204",
                    "start_time": overlap_start,
                    "end_time": overlap_end,
                    "purpose": "Overlapping booking",
                },
            )


def test_invalid_booking_time_format_uses_protocol_error_code(store: BookingStore) -> None:
    with pytest.raises(ValueError, match="E_INVALID_TIME_RANGE"):
        store.create_booking(
            "student",
            {
                "resource_id": "ROOM-204",
                "start_time": "not-a-date",
                "end_time": "2026-06-10T10:00:00Z",
                "purpose": "Invalid date",
            },
        )


def test_booking_duration_limit_is_enforced(store: BookingStore) -> None:
    start_time, end_time = future_slot(days=15, hour=8, duration_hours=25)

    with pytest.raises(ValueError, match="E_INVALID_TIME_RANGE"):
        store.create_booking(
            "student",
            {
                "resource_id": "ROOM-204",
                "start_time": start_time,
                "end_time": end_time,
                "purpose": "Too long",
            },
        )


def test_booking_future_limit_is_enforced(store: BookingStore) -> None:
    start_time, end_time = future_slot(days=120, hour=8)

    with pytest.raises(ValueError, match="E_INVALID_TIME_RANGE"):
        store.create_booking(
            "student",
            {
                "resource_id": "ROOM-204",
                "start_time": start_time,
                "end_time": end_time,
                "purpose": "Too far ahead",
            },
        )


def test_admin_can_cancel_other_user_booking(store: BookingStore) -> None:
    start_time, end_time = future_slot(days=16, hour=8)
    booking = store.create_booking(
        "student",
        {
            "resource_id": "ROOM-207",
            "start_time": start_time,
            "end_time": end_time,
            "purpose": "Admin cancellation test",
        },
    )

    cancelled = store.cancel_booking("admin", "admin", booking["booking_id"])

    assert cancelled["status"] == "cancelled"


def test_idempotency_result_is_persisted(store: BookingStore) -> None:
    response = {"type": "OK", "payload": {"booking_id": "B-1"}}

    store.save_idempotency("IK-1", "fingerprint", response)
    saved = store.get_idempotency("IK-1")

    assert saved == {"fingerprint": "fingerprint", "response": response}
