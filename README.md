# Analyse_auth.py

**Analyse simple des échecs SSH dans `auth.log`**  
Script Python léger pour extraire les IPs à l'origine de tentatives de connexion SSH échouées, compter les occurrences et produire un CSV récapitulatif.

---

## ⚠️ Avertissement légal
N'utilise ce script **que** sur des systèmes dont tu as la permission (ton lab personnel, VM, serveurs dont tu es admin). Scanner / analyser des systèmes tiers sans autorisation est illégal.

---

## Fonctionnalités
- Lecture d'un fichier de logs (par défaut `/var/log/auth.log`)  
- Détection de lignes contenant `Failed password` ou `Invalid user` (logs `sshd`)  
- Comptage des IPs les plus actives (tentatives)  
- Extraction des timestamps `first_seen` et `last_seen` (approximation basée sur l'année courante)  
- Export CSV optionnel (`ip,count,first_seen,last_seen`)  

---

## Prérequis
- Python 3.x
- Le script ne nécessite pas de librairie externe (stdlib seulement).

---
## Améliorations possibles

Support IPv6

Gestion des logs rotés (auth.log.1, auth.log.2.gz)

Intégration avec Filebeat / ELK pour centralisation & dashboards

Ajout d'un mode "monitoring" (exécution récurrente + alertes)

Visualisations graphiques (matplotlib / plotly)
---

## Installation / Utilisation
1. Récupère le script `analyse_auth.py` (copier/coller dans ton repo).
2. Exécute :
```bash
python3 analyse_auth.py
