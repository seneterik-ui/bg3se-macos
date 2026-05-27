from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

EXCEL_PATH = BASE_DIR / "data" / "employees.xlsx"
TEMPLATES_DOCX_DIR = BASE_DIR / "templates_docx"
OUTPUT_DIR = BASE_DIR / "output"
DB_PATH = BASE_DIR / "database" / "hr.db"

SECRET_KEY = "change-me-in-production-please"

TEMPLATES = {
    "attestation_salaire": {
        "label": "Attestation de salaire",
        "icon": "💶",
        "description": "Justificatif de revenus pour banque, bailleur ou administration.",
        "category": "Paie",
        "filename": "attestation_salaire.docx",
        "fields": [
            {"key": "periode", "label": "Période concernée", "type": "text", "placeholder": "Ex. Janvier 2026", "required": True},
            {"key": "destinataire", "label": "Destinataire", "type": "text", "placeholder": "Ex. Banque Populaire", "required": False},
        ],
    },
    "demande_arriere": {
        "label": "Demande de paiement d'arriérés",
        "icon": "📜",
        "description": "Réclamation de sommes dues non versées sur paie antérieure.",
        "category": "Arriérés",
        "filename": "demande_arriere.docx",
        "fields": [
            {"key": "mois_concerne", "label": "Mois concerné", "type": "text", "placeholder": "Ex. Décembre 2025", "required": True},
            {"key": "montant", "label": "Montant réclamé (€)", "type": "number", "placeholder": "Ex. 850.00", "required": True},
            {"key": "motif", "label": "Motif de la demande", "type": "textarea", "placeholder": "Heures supplémentaires non payées, prime omise...", "required": True},
        ],
    },
    "certificat_travail": {
        "label": "Certificat de travail",
        "icon": "📄",
        "description": "Document remis en fin de contrat (obligation légale L1234-19).",
        "category": "Juridique",
        "filename": "certificat_travail.docx",
        "fields": [
            {"key": "date_fin", "label": "Date de fin de contrat", "type": "date", "placeholder": "", "required": True},
            {"key": "motif_fin", "label": "Motif de fin", "type": "select", "options": ["Démission", "Fin CDD", "Rupture conventionnelle", "Licenciement", "Retraite"], "required": True},
        ],
    },
    "demande_mutuelle": {
        "label": "Prise en charge santé / mutuelle",
        "icon": "🏥",
        "description": "Demande d'affiliation, modification ou remboursement mutuelle d'entreprise.",
        "category": "Santé",
        "filename": "demande_mutuelle.docx",
        "fields": [
            {"key": "type_demande", "label": "Type de demande", "type": "select", "options": ["Affiliation", "Ajout d'ayant droit", "Suppression d'ayant droit", "Remboursement", "Dispense"], "required": True},
            {"key": "ayants_droit", "label": "Ayants droit concernés", "type": "text", "placeholder": "Ex. Conjoint, 2 enfants", "required": False},
            {"key": "precisions", "label": "Précisions", "type": "textarea", "placeholder": "Détails complémentaires", "required": False},
        ],
    },
    "attestation_juridique": {
        "label": "Attestation employeur (droit du travail)",
        "icon": "⚖️",
        "description": "Attestation pour démarche juridique, prud'hommes ou administration.",
        "category": "Droit du travail",
        "filename": "attestation_juridique.docx",
        "fields": [
            {"key": "objet", "label": "Objet de l'attestation", "type": "text", "placeholder": "Ex. Inscription Pôle Emploi", "required": True},
            {"key": "destinataire", "label": "Destinataire", "type": "text", "placeholder": "Ex. Pôle Emploi - Agence Paris 11e", "required": True},
            {"key": "details", "label": "Éléments à attester", "type": "textarea", "placeholder": "Précisez les éléments à inclure (ancienneté, poste, etc.)", "required": False},
        ],
    },
}
