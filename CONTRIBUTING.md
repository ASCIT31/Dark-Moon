# 🤝 Contributing to Darkmoon

Merci de votre intérêt pour Darkmoon.

Ce document définit **les règles de contribution**, afin de garantir :
- qualité,
- sécurité,
- maintenabilité.

---

## 1. Philosophie du projet

Darkmoon est :
- open-source,
- orienté sécurité,
- conçu pour être audité.

Toute contribution doit :
- être lisible,
- être justifiée,
- respecter l’architecture existante.

---

## 2. Types de contributions acceptées

- nouveaux outils de pentest
- nouveaux workflows MCP
- améliorations d’agents
- documentation
- correctifs de sécurité

---

## 3. Ajouter un outil

### Où ajouter ?

| Type d’outil | Fichier |
|-----------|--------|
| Binaire | `setup.sh` |
| Python | `setup_py.sh` |
| Ruby | `setup_ruby.sh` |

Règles :
- un outil = un bloc clair
- validation obligatoire
- installation propre

---

## 4. Ajouter un workflow MCP

1. Copier `mcp/src/tools/workflows/TEMPLATE.py`
2. Implémenter une logique cohérente
3. Structurer les outputs
4. Tester localement
5. Documenter

📄 Voir `mcp/WORKFLOW_GUIDE.md`

---

## 5. Ajouter ou modifier un agent

- agents = Markdown
- règles strictes
- MCP obligatoire
- pas de logique dangereuse

👉 Un agent est une **stratégie**, pas un script.

---

## 6. Bonnes pratiques

- ne pas casser la compatibilité
- pas de “quick hacks”
- penser sécurité avant performance
- documenter toute décision

---

## 7. Code of Conduct

- respect
- clarté
- transparence
- sécurité avant ego

---

## 8. Conclusion

Darkmoon est un projet sérieux.

Si vous contribuez :
- faites-le proprement,
- faites-le lisiblement,
- faites-le de manière responsable.

Merci 🙏