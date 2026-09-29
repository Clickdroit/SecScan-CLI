# 🔍 SecScan-CLI — Web Security Posture & SSL/TLS Audit Scanner

**SecScan-CLI** est un outil en ligne de commande moderne et rapide développé en **Python** pour auditer la posture de sécurité d'un site web ou d'une infrastructure en quelques secondes.

Il analyse en profondeur les en-têtes HTTP de sécurité, la configuration cryptographique SSL/TLS, détecte les fichiers sensibles exposés par inadvertance (`.env`, `.git`), attribue un **score global de A+ à F** et génère un rapport de remédiation prêt à l'emploi.

---

## 📋 Aperçu du terminal

```
  ____            ____                      ____ _     ___ 
 / ___|  ___  ___/ ___|  ___ __ _ _ __     / ___| |   |_ _|
 \___ \ / _ \/ __\___ \ / __/ _` | '_ \   | |   | |    | | 
  ___) |  __/ (__ ___) | (_| (_| | | | |  | |___| |___ | | 
 |____/ \___|\___|____/ \___\__,_|_| |_|   \____|_____|___|
                                                            
Target: https://example.com [IP: 93.184.216.34]
Audit Duration: 1.42s

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Category                    ┃ Status ┃ Points ┃ Recommendation                 ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Strict-Transport-Security   │ PASS   │ +15    │ max-age=31536000; includeSub.. │
│ Content-Security-Policy     │ WARN   │ +5     │ Missing object-src directive   │
│ X-Frame-Options             │ PASS   │ +10    │ DENY                           │
│ X-Content-Type-Options      │ PASS   │ +10    │ nosniff                        │
│ SSL/TLS Certificate Valid   │ PASS   │ +20    │ Valid for 74 days (Let's Enc.) │
│ Sensitive File Check (.git) │ PASS   │ +15    │ 404 Not Found (Protected)      │
│ Sensitive File Check (.env) │ PASS   │ +15    │ 404 Not Found (Protected)      │
└─────────────────────────────┴────────┴────────┴────────────────────────────────┘

Final Security Score: 90 / 100 [GRADE: A] 🛡️
```

---

## ✨ Fonctionnalités clés

- **🛡️ Audit des En-têtes HTTP (OWASP Secure Headers) :**
  - Contrôle strict de `HSTS`, `Content-Security-Policy` (CSP), `X-Frame-Options` (anti-clickjacking), `X-Content-Type-Options`, `Referrer-Policy`, et `Permissions-Policy`.
  - Détection des en-têtes qui divulguent la version du serveur (`Server: Apache/2.4`, `X-Powered-By: PHP/7.4`).

- **🔒 Inspection Cryptographique SSL / TLS :**
  - Validité de la chaîne de confiance et date d'expiration du certificat.
  - Détection de l'utilisation de protocoles obsolètes (SSLv3, TLS 1.0, TLS 1.1) et vérification du support TLS 1.2 / 1.3.
  - Identification des suites de chiffrement faibles (Weak Ciphers).

- **🚨 Détection de Fuites de Fichiers & Chemins Critiques :**
  - Vérification de l'exposition accidentelle de fichiers de configuration : `/.env`, `/.git/HEAD`, `/wp-config.php.bak`, `/.DS_Store`, `/phpinfo.php`.

- **📊 Système de Scoring (A+ à F) & Rapports :**
  - Algorithme pondéré attribuant une note de 0 à 100 et un grade (A+, A, B, C, D, E, F).
  - Affichage console riche avec tableaux colorés (**Rich**).
  - Export instantané au format JSON (`--json`) ou Markdown (`--output report.md`).

---

## 🛠️ Stack Technique

- **Langage :** Python 3.10+
- **CLI & Interface :** `Click` / `Typer`, `Rich`
- **Réseau & Requêtes :** `HTTPX` (avec support HTTP/2), `urllib3`
- **Cryptographie :** Module `ssl`, `cryptography`

---

## 🚀 Installation & Utilisation

### Installation
```bash
git clone https://github.com/Clickdroit/SecScan-CLI.git
cd SecScan-CLI
pip install -r requirements.txt
```

### Exemples de commandes
```bash
# Audit standard d'un domaine
python -m secscan audit https://mon-site.fr

# Audit approfondi avec détection de fuites et export JSON
python -m secscan audit https://mon-site.fr --deep --json

# Exporter le rapport complet en Markdown
python -m secscan audit https://mon-site.fr --output audit_rapport.md
```

---

## 📄 Licence
Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus d'informations.
