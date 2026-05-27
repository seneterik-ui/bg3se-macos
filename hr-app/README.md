# Portail RH — Application locale

Application web locale qui reconnaît un collaborateur via un fichier Excel
puis pré-remplit automatiquement des gabarits Word RH (paie, arriérés,
santé, juridique, droit du travail).

## Stack

- **Backend** : Flask 3 + SQLite (privé, local)
- **Excel** : openpyxl
- **Génération de documents** : python-docx (.docx)
- **Front** : HTML / CSS glassmorphisme / vanilla JS

## Design

- **Loi de Jakob** : barre de recherche en haut, fil d'Ariane, stepper
  numéroté, boutons primaires/secondaires identifiables instantanément.
- **Glassmorphisme** : `backdrop-filter: blur(18px)` sur les conteneurs,
  gradients animés en arrière-plan, ombres douces.
- **Lois UI** :
  - *Fitts* : cibles cliquables ≥ 48 px (boutons, liens, champs).
  - *Hick* : 5 catégories maximum sur l'accueil.
  - *Miller* : stepper à 4 étapes.
  - *Feedback immédiat* : toasts, spinners, validation live, animations
    courtes (150–280 ms).

## Suivi UX

Tous les événements sont enregistrés dans `database/hr.db` (SQLite local) :

- `page_view`, `page_leave` (durée passée)
- `search_started`, `search` (avec nombre de résultats)
- `employee_selected`, `template_selected`
- `card_hover` (intérêt > 500 ms)
- `form_opened`, `form_submitted`, `form_validation_failed`
- `document_generated`, `document_downloaded`
- `error`

Le dashboard `/dashboard` affiche : KPI globaux, entonnoir de conversion,
top collaborateurs, documents par type, 15 derniers événements.

## Installation

```bash
cd hr-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Initialiser la base + créer fichier Excel + gabarits d'exemple
python scripts/init_db.py
python scripts/seed_excel.py
python scripts/seed_templates.py

# Lancer l'application
python app.py
```

L'application est accessible sur **http://127.0.0.1:5000**.

## Personnalisation

### Adapter le fichier Excel

Remplacer `data/employees.xlsx` par votre fichier RH réel. Les colonnes
attendues sont (en minuscules, sans accents) :

```
matricule, nom, prenom, date_naissance, sexe,
email, telephone, adresse,
date_embauche, type_contrat, poste, service,
salaire_brut, manager, numero_ss, iban
```

Toute colonne supplémentaire est conservée et utilisable comme
placeholder `{{nom_colonne}}` dans les gabarits.

### Adapter les gabarits Word

Les gabarits sont dans `templates_docx/`. Ce sont des fichiers `.docx`
classiques où chaque variable est notée `{{nom_variable}}`. Les
variables disponibles incluent toutes les colonnes du fichier Excel, plus :

- `{{date_jour}}` — date du jour (JJ/MM/AAAA)
- `{{lieu}}` — lieu (Paris par défaut, modifiable dans `doc_generator.py`)
- `{{civilite}}` — Madame / Monsieur (déduite de `sexe`)
- `{{nom_complet}}` — prénom + nom

Plus les champs spécifiques à chaque formulaire (voir `config.py`).

### Ajouter un nouveau type de demande

1. Ajouter une entrée dans `TEMPLATES` (config.py) avec ses champs.
2. Créer `templates_docx/nouveau_type.docx` avec les placeholders.
3. C'est tout — l'UI se met à jour automatiquement.

## Structure

```
hr-app/
├── app.py                       # Routes Flask
├── config.py                    # Définition des gabarits
├── requirements.txt
├── data/
│   └── employees.xlsx           # Fichier RH (créé par seed_excel.py)
├── database/
│   └── hr.db                    # SQLite — créé à l'init
├── templates_docx/              # Gabarits Word avec {{placeholders}}
├── output/                      # Documents générés
├── modules/
│   ├── db.py                    # Schéma SQLite + helpers
│   ├── excel_loader.py          # Lecture/recherche Excel
│   ├── doc_generator.py         # Remplissage gabarits
│   └── tracker.py               # Tracking UX
├── scripts/
│   ├── init_db.py
│   ├── seed_excel.py            # Génère un Excel d'exemple
│   └── seed_templates.py        # Génère 5 gabarits .docx d'exemple
├── templates/                   # Vues Jinja2
└── static/
    ├── css/style.css            # Glassmorphisme + composants
    └── js/app.js                # Recherche live + feedback UX
```

## Sécurité / vie privée

- 100 % local, aucune requête sortante.
- `database/hr.db` reste sur votre machine.
- Pour la production, changer `SECRET_KEY` dans `config.py` et servir
  derrière un reverse proxy avec HTTPS.
