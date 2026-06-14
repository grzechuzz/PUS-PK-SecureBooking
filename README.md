# SecureBookingApp

Aplikacja SecureBooking wykorzystująca protokół SecureBooking Protocol.

## Zawartość

- `securebooking/protocol.py` - ramkowanie JSON, walidacja pól wspólnych, tworzenie `OK` i `ERROR`.
- `securebooking/store.py` - SQLite: użytkownicy testowi, zasoby, rezerwacje, idempotencja.
- `securebooking/server.py` - serwer TCP/TLS obsługujący SecureBooking Protocol.
- `securebooking/client.py` - klient CLI.
- `securebooking/demo.py` - automatyczne scenariusze demonstracyjne.
- `docs/runbook.md` - instrukcja uruchomienia i demo.

## Użytkownicy testowi

| Login | Hasło | Rola |
| --- | --- | --- |
| `student` | `student123` | `user` |
| `grzegorz` | `pus123` | `user` |
| `patryk` | `pus123` | `user` |
| `admin` | `admin123` | `admin` |

## Szybki start

```bash
./scripts/generate_certs.sh
./scripts/reset_data.sh
python3 -m securebooking.server
```

W drugim terminalu:

```bash
python3 -m securebooking.demo
```

## Przykładowe komendy klienta

```bash
python3 -m securebooking.client resources
python3 -m securebooking.client resources --resource-type room
python3 -m securebooking.client ping
python3 -m securebooking.client book --resource-id ROOM-204 --start 2026-06-20T08:00:00Z --end 2026-06-20T10:00:00Z
python3 -m securebooking.client bookings
python3 -m securebooking.client unauthorized
```

## Testy i CI

Testy lokalne:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m py_compile securebooking/*.py tests/*.py
.venv/bin/pytest -v
```

Workflow GitHub Actions znajduje się w `.github/workflows/ci.yml`. Po wypchnięciu projektu do repozytorium instaluje zależności testowe, uruchamia kompilację modułów, testy `pytest` i demo integracyjne klient-serwer.
