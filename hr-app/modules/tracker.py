import json
import uuid
from flask import request, session
from .db import execute, query


def ensure_session():
    """Create a session UID on first visit, persist across requests."""
    if "uid" not in session:
        session["uid"] = uuid.uuid4().hex
        execute(
            "INSERT OR IGNORE INTO sessions(session_uid, ip, user_agent) VALUES (?, ?, ?)",
            (session["uid"], request.remote_addr or "", request.user_agent.string[:255]),
        )
    return session["uid"]


def track(event_type, payload=None, employee_matricule=None, template_key=None, duration_ms=None):
    """Record a user-journey event."""
    uid = ensure_session()
    execute(
        """INSERT INTO events(session_uid, event_type, payload, employee_matricule, template_key, duration_ms)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (uid, event_type, json.dumps(payload) if payload else None,
         employee_matricule, template_key, duration_ms),
    )


def record_document(employee, template_key, filename):
    uid = session.get("uid")
    execute(
        """INSERT INTO documents(session_uid, employee_matricule, employee_name, template_key, output_filename)
           VALUES (?, ?, ?, ?, ?)""",
        (uid, employee.get("matricule"),
         f"{employee.get('prenom','')} {employee.get('nom','')}".strip(),
         template_key, filename),
    )


def dashboard_stats():
    total_sessions = query("SELECT COUNT(*) AS n FROM sessions")[0]["n"]
    total_docs = query("SELECT COUNT(*) AS n FROM documents")[0]["n"]
    total_events = query("SELECT COUNT(*) AS n FROM events")[0]["n"]

    funnel = query("""
        SELECT event_type, COUNT(DISTINCT session_uid) AS sessions
        FROM events
        WHERE event_type IN ('search', 'employee_selected', 'template_selected', 'document_generated')
        GROUP BY event_type
    """)
    funnel_map = {row["event_type"]: row["sessions"] for row in funnel}
    funnel_ordered = [
        {"step": "Recherche", "n": funnel_map.get("search", 0)},
        {"step": "Employé sélectionné", "n": funnel_map.get("employee_selected", 0)},
        {"step": "Type de demande choisi", "n": funnel_map.get("template_selected", 0)},
        {"step": "Document généré", "n": funnel_map.get("document_generated", 0)},
    ]

    docs_by_template = query("""
        SELECT template_key, COUNT(*) AS n
        FROM documents
        GROUP BY template_key
        ORDER BY n DESC
    """)

    top_employees = query("""
        SELECT employee_name, COUNT(*) AS n
        FROM documents
        WHERE employee_name IS NOT NULL AND employee_name != ''
        GROUP BY employee_name
        ORDER BY n DESC
        LIMIT 5
    """)

    recent_events = query("""
        SELECT event_type, employee_matricule, template_key, created_at
        FROM events
        ORDER BY created_at DESC
        LIMIT 15
    """)

    return {
        "total_sessions": total_sessions,
        "total_docs": total_docs,
        "total_events": total_events,
        "funnel": funnel_ordered,
        "docs_by_template": docs_by_template,
        "top_employees": top_employees,
        "recent_events": recent_events,
    }
