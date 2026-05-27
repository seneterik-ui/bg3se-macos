import sqlite3
from contextlib import contextmanager
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_uid TEXT PRIMARY KEY,
    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip          TEXT,
    user_agent  TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uid         TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    payload             TEXT,
    employee_matricule  TEXT,
    template_key        TEXT,
    duration_ms         INTEGER,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uid         TEXT,
    employee_matricule  TEXT,
    employee_name       TEXT,
    template_key        TEXT,
    output_filename     TEXT,
    generated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_uid);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_docs_template  ON documents(template_key);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def query(sql, params=()):
    with get_conn() as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def execute(sql, params=()):
    with get_conn() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid
