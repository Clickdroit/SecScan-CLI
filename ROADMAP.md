# 🗺️ Feuille de Route (Roadmap) — SecScan-CLI

Ce document décrit les étapes de développement pour construire **SecScan-CLI**, du prototype d'audit d'en-têtes HTTP jusqu'à un scanner d'infrastructure complet avec rapports multi-formats.

---

## 📌 Phase 1 : Moteur d'Analyse des En-têtes HTTP
- [ ] Initialiser le package Python avec `Click` ou `Typer` et `Rich`.
- [ ] Créer la commande principale `secscan audit <url>`.
- [ ] Implémenter l'analyseur des en-têtes de sécurité recommandés par l'OWASP :
  - `Strict-Transport-Security` (présence, `max-age`, `includeSubDomains`, `preload`).
  - `Content-Security-Policy` (présence, vérification des directives critiques `default-src`, `script-src`).
  - `X-Frame-Options` (`DENY` ou `SAMEORIGIN`).
  - `X-Content-Type-Options` (`nosniff`).
  - `Referrer-Policy`.
  - `Permissions-Policy`.
- [ ] Détecter et avertir en cas de fuite d'informations via `Server` et `X-Powered-By`.

---

## 📌 Phase 2 : Inspecteur SSL / TLS
- [ ] Implémenter une socket SSL directe pour extraire les métadonnées du certificat X.509 :
  - Émetteur (Issuer), Sujet (Subject), Liste des SAN (Subject Alternative Names).
  - Date de validité et calcul du nombre de jours restants avant expiration.
- [ ] Tester les versions de protocoles supportées par le serveur distant (flaguer si TLS 1.0 ou TLS 1.1 sont acceptés).
- [ ] Évaluer la robustesse de la suite de chiffrement négociée.

---

## 📌 Phase 3 : Détecteur de Fichiers & Secrets Exposés (Leak Finder)
- [ ] Créer une liste de dictionnaires de chemins sensibles courants :
  - `/.env`, `/.env.local`, `/.env.production`
  - `/.git/HEAD`, `/.git/config`
  - `/wp-config.php.bak`, `/configuration.php.old`
  - `/phpinfo.php`, `/.DS_Store`, `/crossdomain.xml`
- [ ] Effectuer des requêtes HTTP asynchrones (via `httpx.AsyncClient`) avec gestion des redirections pour valider le statut réel du fichier (vérifier le contenu et pas seulement le code HTTP 200).

---

## 📌 Phase 4 : Algorithme de Scoring & Interface Rich
- [ ] Définir le barème de points (Base 100 points) :
  - En-têtes essentiels : +40 pts
  - Configuration SSL/TLS irréprochable : +30 pts
  - Absence totale de fuite de fichiers : +30 pts
  - Pénalités sévères pour protocoles obsolètes ou fichiers `.env` téléchargeables.
- [ ] Convertir la note numérique en Grade :
  - 95-100 : A+ | 85-94 : A | 75-84 : B | 65-74 : C | 50-64 : D | < 50 : F.
- [ ] Concevoir le tableau d'affichage console avec **Rich** (couleurs vert/orange/rouge, barre de progression animée).

---

## 📌 Phase 5 : Export Multi-Formats & Intégration CI/CD
- [ ] Ajouter l'option `--json` pour sortir les résultats au format JSON machine-readable.
- [ ] Ajouter l'option `--output <file.md>` pour générer un rapport d'audit Markdown prêt pour un client.
- [ ] Code d'exit terminal configurable : renvoyer un code d'erreur `1` en cas de note inférieure à un seuil défini (idéal pour intégrer SecScan dans des pipelines **GitHub Actions** de CI/CD).
