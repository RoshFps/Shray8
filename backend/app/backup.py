"""Consistent SQLite backup, safe while the dashboard is running.

Usage (writes a gzip-compressed copy to stdout):
    python -m app.backup > esd-backup.db.gz
"""

import gzip
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from .db import db_path


def backup_to(dest: Path) -> None:
    """Copy the live database to `dest` using SQLite's online backup API."""
    src = sqlite3.connect(db_path(), timeout=10)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "snapshot.db"
        backup_to(snapshot)
        with open(snapshot, "rb") as f, gzip.GzipFile(fileobj=sys.stdout.buffer, mode="wb") as out:
            shutil.copyfileobj(f, out)


if __name__ == "__main__":
    main()
