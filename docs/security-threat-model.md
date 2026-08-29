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

Frontière de **minimisation des données** entre le modèle et l'exécution (`mcp/src/privacy/`). Sur le chemin des **appels d'outils MCP et de leurs sorties**, les valeurs sensibles auto-détectables — **IP, hostnames internes, domaines, URLs, emails, chemins** — sont remplacées par des **placeholders déterministes** (`IP_PRIVATE_001`, `HOST_INTERNAL_001`…) avant d'atteindre le modèle. Ces catégories forment le **périmètre par défaut** (`privacy.DEFAULT_CATEGORIES`, source unique partagée par le serveur et le vault). Les vraies valeurs sont réinjectées **localement, juste avant l'exécution de l'outil**, puis re-masquées dans toute sortie avant retour au modèle.

| Élément | Mesure |
|------|-------|
| Tokenisation | Déterministe par session (`PrivacyVault`) |
| Mapping | Chiffré (Fernet) + dédup HMAC ; **aucune valeur brute** retenue/loggée ; TTL |
| Réhydratation | *Context-aware* (`CommandGateway`), jamais un remplacement global |
| Exfiltration | **Valeur retenue, commande exécutée** : placeholder dans query URL / host externe littéral / body sortant / `/dev/tcp` / pipeline vers un sink hors cible. Le tiers reçoit le token, jamais la valeur |
| Secrets | `CRED` injecté **localement et uniquement** vers la cible protégée ; jamais dans un sink d'impression, jamais à côté d'une destination littérale |
| Injection shell | Valeur réhydratée **quotée pour son contexte** (hors quotes / `'…'` / `"…"`), y compris dans un `bash -c` imbriqué |
| Config | `DARKMOON_PRIVACY` (on par défaut) · `DARKMOON_PRIVACY_CATEGORIES` · `DARKMOON_PRIVACY_POLICY` · `DARKMOON_PRIVACY_CRED_INJECT` |

#### Politique : dégrader, ne pas refuser

Élargir le périmètre par défaut à `URL`/`DOMAIN`/`PATH` (issue #40) a eu un effet de bord majeur : **presque toute** commande de pentest porte désormais un placeholder, donc chaque règle d'exfiltration se déclenchait sur du travail légitime. Un gateway qui refuse devient un bloqueur de campagne — 9 commandes sur 15 étaient rejetées, et une URL contenant `?` ne pouvait plus être réhydratée du tout, le garde-fou anti-injection rejetant le métacaractère ([PR #42](https://github.com/ASCIT31/Dark-Moon/pull/42)).

Ce n'est jamais le blocage qui protégeait l'opérateur. Deux choses le font :

1. le modèle ne reçoit **que** des placeholders, et
2. **chaque octet** de sortie d'outil est re-tokenisé avant de lui revenir.

Le gateway ne refuse donc plus une commande. Quand un placeholder se trouve à un endroit où sa vraie valeur ne doit pas aller, la commande s'exécute **avec le placeholder laissé en place** : le tiers reçoit `IP_PRIVATE_001`, la commande tourne, la campagne continue. C'est `GatewayPolicy.DEGRADE`, le défaut. Le modèle est informé des valeurs retenues (`PRIVACY : n value(s) kept tokenized`) — une information, pas une erreur.

`DARKMOON_PRIVACY_POLICY=strict` restaure le refus pur et dur pour qui le souhaite. Une valeur non reconnue retombe sur `degrade` : une faute de frappe dans l'environnement d'un opérateur ne doit jamais retransformer le gateway en bloqueur.

**Périmètre actuel & limites connues** (réf. [issue #40](https://github.com/ASCIT31/Dark-Moon/issues/40)) :
- Le périmètre par défaut couvre les catégories **auto-détectables** listées ci-dessus (correctif : `URL`/`DOMAIN`/`PATH` sont désormais inclus par défaut — auparavant ils pouvaient échapper à la tokenisation). Un `DARKMOON_PRIVACY_CATEGORIES` absent ou invalide **retombe sur ce défaut complet**, il ne peut plus le rétrécir silencieusement.
- Un nom de fichier n'est pas un hôte. `_DOMAIN_RE` ne sait pas distinguer `index.php` de `acme-corp.com` ; depuis que `DOMAIN` est actif par défaut, chaque nom de fichier d'une sortie d'outil frappait un placeholder `DOMAIN_00N`. Pire qu'une fuite : le modèle ne pouvait plus lire une extension ni repérer un motif, et un `nuclei -u DOMAIN_001` ultérieur se résolvait silencieusement vers `index.php` au lieu de la cible. Un label final correspondant à une extension connue n'est donc plus tokenisé.
- **Usernames** (`USER`) reste **register-only** : pas d'auto-détection depuis du texte libre.
- Les **credentials en clair** sont désormais auto-détectés dans les sorties d'outil (flag `-p`, `clé: valeur`, en-tête `Authorization`, userinfo d'URI, paire de hashes NT) et enregistrés en `CRED`. Auparavant `CRED` n'avait **aucun** chemin d'enregistrement en production : un mot de passe imprimé par un outil arrivait tel quel dans le contexte du modèle alors que la documentation promettait l'inverse.
- Un `CRED` est **réinjecté localement** dans une commande dont la destination est la cible protégée — c'est ce qui rend le test authentifié possible sans que le modèle ne détienne jamais le secret. Il n'est jamais restauré dans un sink d'impression, ni à côté d'une destination littérale, ni sans cible protégée nommée dans la même commande, ni dans un paramètre de workflow. `DARKMOON_PRIVACY_CRED_INJECT=0` désactive complètement l'injection.
- Le **prompt initial de campagne** (`TARGET`/`CREDS`/`TOKEN` fournis au lancement) est actuellement transmis tel quel au modèle : la tokenisation **pré-modèle** du prompt (vault de session partagé entre la couche prompt et le MCP) est un chantier de frontière de confiance planifié, non encore livré. Tant qu'il n'est pas en place, ne pas considérer les secrets passés dans le prompt de lancement comme masqués vis-à-vis d'un fournisseur de modèle cloud.

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