import re
from datetime import datetime
from docx import Document
from config import TEMPLATES_DOCX_DIR, OUTPUT_DIR, TEMPLATES

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def _replace_in_paragraph(paragraph, mapping):
    """Replace {{key}} placeholders while preserving paragraph formatting."""
    full_text = "".join(run.text for run in paragraph.runs)
    if "{{" not in full_text:
        return
    new_text = PLACEHOLDER_RE.sub(lambda m: str(mapping.get(m.group(1), m.group(0))), full_text)
    if new_text == full_text:
        return
    for run in paragraph.runs:
        run.text = ""
    if paragraph.runs:
        paragraph.runs[0].text = new_text
    else:
        paragraph.add_run(new_text)


def _walk_replace(doc, mapping):
    for p in doc.paragraphs:
        _replace_in_paragraph(p, mapping)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    _replace_in_paragraph(p, mapping)


def generate(template_key, employee, form_data):
    """Fill the template_key gabarit with employee + form_data and return output path."""
    cfg = TEMPLATES[template_key]
    src = TEMPLATES_DOCX_DIR / cfg["filename"]
    if not src.exists():
        raise FileNotFoundError(f"Gabarit introuvable : {src}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now()
    mapping = {
        # Employee fields
        "matricule": employee.get("matricule", ""),
        "nom": employee.get("nom", ""),
        "prenom": employee.get("prenom", ""),
        "nom_complet": f"{employee.get('prenom', '')} {employee.get('nom', '')}".strip(),
        "date_naissance": employee.get("date_naissance", ""),
        "sexe": employee.get("sexe", ""),
        "email": employee.get("email", ""),
        "telephone": employee.get("telephone", ""),
        "adresse": employee.get("adresse", ""),
        "date_embauche": employee.get("date_embauche", ""),
        "type_contrat": employee.get("type_contrat", ""),
        "poste": employee.get("poste", ""),
        "service": employee.get("service", ""),
        "salaire_brut": employee.get("salaire_brut", ""),
        "manager": employee.get("manager", ""),
        "numero_ss": employee.get("numero_ss", ""),
        "iban": employee.get("iban", ""),
        # Document metadata
        "date_jour": today.strftime("%d/%m/%Y"),
        "lieu": "Paris",
        "civilite": "Madame" if str(employee.get("sexe", "")).upper().startswith("F") else "Monsieur",
    }
    # Merge form-specific fields (override on collision)
    mapping.update({k: ("" if v is None else str(v)) for k, v in form_data.items()})

    doc = Document(src)
    _walk_replace(doc, mapping)

    safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", f"{employee.get('nom','X')}_{employee.get('prenom','X')}")
    out_name = f"{template_key}_{safe_name}_{today:%Y%m%d_%H%M%S}.docx"
    out_path = OUTPUT_DIR / out_name
    doc.save(out_path)
    return out_path
