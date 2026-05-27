"""Initialize the SQLite database (creates schema if missing)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.db import init_db, DB_PATH

if __name__ == "__main__":
    init_db()
    print(f"Base initialisée : {DB_PATH}")
