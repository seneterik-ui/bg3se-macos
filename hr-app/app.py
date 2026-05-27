from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify, send_file,
    redirect, url_for, flash, session
)

from config import SECRET_KEY, TEMPLATES, OUTPUT_DIR
from modules import excel_loader, doc_generator, tracker
from modules.db import init_db


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.jinja_env.globals["TEMPLATES"] = TEMPLATES


@app.before_request
def _ensure_session():
    if request.endpoint and request.endpoint != "static":
        tracker.ensure_session()


@app.route("/")
def index():
    tracker.track("page_view", payload={"page": "index"})
    return render_template("index.html")


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    results = excel_loader.search(q, limit=8) if q else []
    tracker.track("search", payload={"q": q, "results": len(results)})
    safe = [
        {
            "matricule": r.get("matricule", ""),
            "nom": r.get("nom", ""),
            "prenom": r.get("prenom", ""),
            "poste": r.get("poste", ""),
            "service": r.get("service", ""),
            "email": r.get("email", ""),
        }
        for r in results
    ]
    return jsonify({"results": safe})


@app.route("/employee/<matricule>")
def employee(matricule):
    emp = excel_loader.get_by_matricule(matricule)
    if not emp:
        flash("Employé introuvable dans le fichier RH.", "error")
        return redirect(url_for("index"))
    tracker.track("employee_selected", employee_matricule=matricule)
    return render_template("employee.html", employee=emp)


@app.route("/employee/<matricule>/request/<template_key>", methods=["GET", "POST"])
def request_form(matricule, template_key):
    emp = excel_loader.get_by_matricule(matricule)
    if not emp:
        flash("Employé introuvable.", "error")
        return redirect(url_for("index"))
    if template_key not in TEMPLATES:
        flash("Type de demande inconnu.", "error")
        return redirect(url_for("employee", matricule=matricule))

    cfg = TEMPLATES[template_key]

    if request.method == "POST":
        form_data = {f["key"]: request.form.get(f["key"], "").strip() for f in cfg["fields"]}
        missing = [f["label"] for f in cfg["fields"]
                   if f.get("required") and not form_data.get(f["key"])]
        if missing:
            flash("Champs requis manquants : " + ", ".join(missing), "error")
            return render_template("form.html", employee=emp,
                                   template_key=template_key, cfg=cfg,
                                   form_data=form_data)
        try:
            out_path = doc_generator.generate(template_key, emp, form_data)
        except Exception as e:
            tracker.track("error", payload={"step": "generate", "msg": str(e)},
                          employee_matricule=matricule, template_key=template_key)
            flash(f"Erreur génération document : {e}", "error")
            return render_template("form.html", employee=emp,
                                   template_key=template_key, cfg=cfg,
                                   form_data=form_data)

        tracker.track("document_generated", payload=form_data,
                      employee_matricule=matricule, template_key=template_key)
        tracker.record_document(emp, template_key, out_path.name)
        return redirect(url_for("success", matricule=matricule,
                                template_key=template_key, filename=out_path.name))

    tracker.track("template_selected", employee_matricule=matricule, template_key=template_key)
    return render_template("form.html", employee=emp, template_key=template_key,
                           cfg=cfg, form_data={})


@app.route("/success/<matricule>/<template_key>/<filename>")
def success(matricule, template_key, filename):
    emp = excel_loader.get_by_matricule(matricule)
    cfg = TEMPLATES.get(template_key)
    if not emp or not cfg:
        return redirect(url_for("index"))
    file_path = OUTPUT_DIR / filename
    if not file_path.exists():
        flash("Document introuvable.", "error")
        return redirect(url_for("employee", matricule=matricule))
    return render_template("success.html", employee=emp, cfg=cfg,
                           template_key=template_key, filename=filename)


@app.route("/download/<filename>")
def download(filename):
    safe = Path(filename).name
    file_path = OUTPUT_DIR / safe
    if not file_path.exists() or not file_path.is_file():
        flash("Fichier introuvable.", "error")
        return redirect(url_for("index"))
    tracker.track("document_downloaded", payload={"filename": safe})
    return send_file(file_path, as_attachment=True, download_name=safe)


@app.route("/dashboard")
def dashboard():
    stats = tracker.dashboard_stats()
    tracker.track("page_view", payload={"page": "dashboard"})
    return render_template("dashboard.html", stats=stats, templates=TEMPLATES)


@app.route("/api/track", methods=["POST"])
def api_track():
    """Front-end UX events (focus, hover-time, abandon, etc.)."""
    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type") or "ui_event"
    tracker.track(
        event_type,
        payload=data.get("payload"),
        employee_matricule=data.get("employee_matricule"),
        template_key=data.get("template_key"),
        duration_ms=data.get("duration_ms"),
    )
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
