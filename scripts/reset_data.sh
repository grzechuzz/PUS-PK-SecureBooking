#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
rm -f "$BASE_DIR/data/securebooking.db" "$BASE_DIR/data/securebooking.db-shm" "$BASE_DIR/data/securebooking.db-wal"
echo "Removed SQLite runtime data."
