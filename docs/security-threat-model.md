# 🔐 Darkmoon — Threat Model & Security Design

Ce document décrit le **threat model de Darkmoon lui-même**.

Objectif :
- comprendre les surfaces d’attaque,
- justifier les choix d’architecture,
- démontrer que Darkmoon est **conçu de manière défensive**, malgré sa vocation offensive.

Public cible :
- RSSI
- auditeurs
- architectes sécurité
- clients exigeants

---

## 1. Principe fondamental

Darkmoon repose sur un principe non négociable :

> **L’IA ne doit jamais pouvoir exécuter librement du code.**

Tout est construit autour de cette contrainte.

---

## 2. Actifs à protéger

| Actif | Description |
|-----|------------|
| Host utilisateur | Système de l’opérateur |
| Clés API LLM | Accès aux modèles |
| Toolbox | Outils de pentest |
| Configuration OpenCode | Agents, prompts |
| Résultats de scan | Données sensibles |

---

## 3. Modèle de menace global

Menaces considérées :

- prompt injection
- exécution de commandes arbitraires
- fuite de secrets
- escalade de privilèges
- sortie de périmètre Docker
- abus du LLM

---

## 4. Frontières de sécurité (défense en profondeur)

### 4.1 IA ↔ Exécution

| Élément | Mesure |
|------|-------|
| Agents | Markdown auditables |
| IA | Aucune commande directe |
| MCP | Seul point d’exécution |

👉 **Barrière la plus importante**.

---

### 4.2 MCP ↔ Toolbox

| Élément | Mesure |
|------|-------|
| Exécution | Docker isolé |
| Outils | Whitelist |
| Timeouts | Contrôlés |
| Parsing | Structuré |

---

### 4.3 Toolbox ↔ Host

| Élément | Mesure |
|------|-------|
| Isolation | Docker |
| Volumes | Contrôlés |
| Réseau | Limité |
| Permissions | Root maîtrisé |

### 4.4 Données ↔ LLM (Privacy Gateway — v1.2.0)

Frontière de **minimisation des données** entre le modèle et l'exécution (`mcp/src/privacy/`). Le LLM ne reçoit **jamais** les vraies valeurs sensibles (IP, hostnames, domaines, URLs, emails, identifiants, chemins internes) : il ne manipule que des **placeholders déterministes** (`IP_PRIVATE_001`, `HOST_INTERNAL_001`…). Les vraies valeurs sont réinjectées **localement, juste avant l'exécution de l'outil**, puis re-masquées dans toute sortie avant retour au modèle → aucune donnée sensible ne quitte le périmètre vers le fournisseur du modèle.

| Élément | Mesure |
|------|-------|
| Tokenisation | Déterministe par session (`PrivacyVault`) |
| Mapping | Chiffré (Fernet) + dédup HMAC ; **aucune valeur brute** retenue/loggée ; TTL |
| Réhydratation | *Context-aware* (`CommandGateway`), jamais un remplacement global |
| Exfiltration | Bloquée : placeholder dans query URL / host externe littéral / echo-print / body sortant / `/dev/tcp` / nc-telnet hors cible |
| Secrets | `CRED` jamais restauré dans une commande exécutée |
| Config | `DARKMOON_PRIVACY` (on par défaut) · `DARKMOON_PRIVACY_CATEGORIES` |

Cœur open-source ; durcissement entreprise (vault scellé par le runtime guard, audit trail, mention conformité dans le rapport signé) en édition Pro.

---

## 5. Gestion des secrets

- Clés API **jamais** hardcodées
- `.env` hors image
- `auth.json` généré dynamiquement
- Volumes persistés côté utilisateur

---

## 6. Prompt Injection & LLM Safety

Mesures :

- agents stricts (pas de raisonnement exposé),
- MCP obligatoire,
- pas d’auto-modification des règles,
- pas d’input utilisateur dynamique non contrôlé.

👉 Une injection ne permet **pas** d’exécuter du code.

---

## 7. Risques assumés

| Risque | Justification |
|-----|---------------|
| Outils offensifs | Cœur du produit |
| Root dans toolbox | Nécessaire |
| Docker socket | Maîtrisé |

👉 Ces risques sont **connus, contrôlés et documentés**.

---

## 8. Ce que Darkmoon ne fait PAS

- pas d’auto-propagation,
- pas de persistance hors périmètre,
- pas d’exploitation destructive,
- pas d’exécution hors scope.

---

## 9. Conclusion sécurité

Darkmoon est :
- offensif par vocation,
- défensif par conception,
- contrôlé par architecture.

👉 **La sécurité est une contrainte fondatrice, pas un ajout.**