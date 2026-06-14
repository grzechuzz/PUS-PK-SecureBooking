# Instrukcja uruchomienia

## Wymagania środowiskowe

- Python 3.10 lub nowszy.
- OpenSSL dostępny w systemie.
- System Linux albo WSL.
- Aplikacja serwera i klienta nie wymaga zewnętrznych bibliotek Pythona.

## Przygotowanie certyfikatów

```bash
./scripts/generate_certs.sh
```

Skrypt tworzy:

- `certs/server.crt`,
- `certs/server.key`,
- `certs/ca.crt`.

Klient używa `ca.crt` do weryfikacji certyfikatu serwera.

## Reset danych demonstracyjnych

```bash
./scripts/reset_data.sh
```

Komenda usuwa bazę SQLite z poprzednich uruchomień. Przy następnym starcie serwer ponownie tworzy tabele oraz dane startowe.

## Uruchomienie serwera

```bash
python3 -m securebooking.server --host 127.0.0.1 --port 7444
```

Serwer nasłuchuje na TCP/TLS i obsługuje ramki SecureBooking Protocol.

## Uruchomienie klienta

Pobranie zasobów:

```bash
python3 -m securebooking.client resources
```

Pobranie tylko sal:

```bash
python3 -m securebooking.client resources --resource-type room
```

Sprawdzenie keep-alive:

```bash
python3 -m securebooking.client ping
```

Utworzenie rezerwacji:

```bash
python3 -m securebooking.client book \
  --resource-id ROOM-204 \
  --start 2026-06-20T08:00:00Z \
  --end 2026-06-20T10:00:00Z \
  --purpose "Spotkanie projektowe"
```

Lista rezerwacji:

```bash
python3 -m securebooking.client bookings
```

Próba operacji bez logowania:

```bash
python3 -m securebooking.client unauthorized
```

## Demo

Automatyczne demo:

```bash
python3 -m securebooking.demo
```

Demo pokazuje:

1. poprawną rezerwację,
2. konflikt terminu,
3. operację bez uwierzytelnienia,
4. ponowienie operacji z tym samym `idempotency_key`,
5. niepoprawny JSON.


## Znane ograniczenia

- MVP używa SQLite zamiast osobnego serwera bazy danych.
- Sesje są utrzymywane w pamięci procesu serwera.
- Wyniki operacji idempotentnych są zapisywane w SQLite.
- Klient jest aplikacją CLI, bez GUI.
