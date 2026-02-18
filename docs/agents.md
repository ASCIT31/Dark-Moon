# 🤖 Darkmoon — Agents IA

Ce document décrit **le fonctionnement des agents IA dans Darkmoon** :
- leur rôle,
- leur structure,
- leurs règles,
- et comment en créer ou modifier.

Public cible :
- pentesters avancés
- créateurs d’agents
- chercheurs sécurité
- contributeurs

---

## 1. Qu’est-ce qu’un agent Darkmoon ?

Un agent Darkmoon est :
- un **fichier Markdown**,
- chargé par OpenCode,
- qui définit **un comportement autonome**,
- et pilote le MCP pour exécuter des actions réelles.

👉 Ce n’est **pas** un prompt classique.
👉 C’est une **stratégie opérationnelle complète**.

---

## 2. Philosophie agentique

Les agents Darkmoon sont conçus pour :

- agir **sans poser de questions**,
- supposer une autorisation explicite,
- enchaîner automatiquement les actions,
- privilégier la profondeur plutôt que la vitesse,
- corréler les résultats.

Un agent **ne demande pas** :
- “veux-tu continuer ?”
- “quel est le scope ?”

👉 Le scope est **déjà défini par l’utilisateur**.

---

## 3. Structure d’un agent Darkmoon

Un agent est un fichier Markdown structuré.

### Exemple simplifié

```markdown
---
id: pentest-web
name: pentest-web
description: Fully autonomous pentest agent
---

You are an autonomous AI cybersecurity agent.
````

### 3.1 Liste des agents

Il existe 4 agents à ce jour:

* `pentest-web` est l'agent dédié au pentest applicatif web, tente des attaques de type XSS,SQLi, SSRF, XXE etc.
* `pentest-ad` est l'agent de pentest dédié au pentest d'infrastructure windows et active directory (ADDS, SMB, Windows etc).
* `pentest-kubernetes` est l'agent de pentest dédié au pentest de surface d'attaque pour un cluster kubernetes.
* `pentest-network` est l'agent de pentest dédié au attaques réseaux d'infrastructure (FTP, FTPS, SFTP, SSH, TELNET, SMTP, SNMP etc)

### Sections courantes

* métadonnées (`id`, `name`, `description`)
* règles d’exécution
* capacités
* règles de communication
* règles d’appel MCP
* contraintes de sécurité

---

## 4. Exemple réel : pentest-web

L’agent `pentest-web` est :

* totalement autonome,
* orienté pentest réel,
* agressif mais non destructif,
* basé **exclusivement sur MCP**.

Il :

* choisit lui-même les workflows,
* peut exécuter directement des outils via MCP,
* corrèle les résultats entre étapes,
* itère jusqu’à épuisement des vecteurs.

👉 C’est un **pentester IA**, pas un assistant.

---

## 5. Règles critiques imposées aux agents

### 5.1 Autonomie

Un agent :

* ne demande jamais confirmation,
* ne demande jamais d’input utilisateur,
* agit immédiatement.

---

### 5.2 MCP-only

Un agent :

* **ne touche jamais Docker**,
* **ne lance jamais d’outil directement**,
* passe toujours par le MCP.

Cela garantit :

* auditabilité,
* contrôle,
* sécurité.

---

### 5.3 Communication

Les agents :

* minimisent les messages utilisateur,
* privilégient les appels d’outils,
* n’exposent jamais leur raisonnement interne.

---

## 6. Où vivent les agents

### Avant build

```
conf/agents/
```

Ces agents sont :

* intégrés dans l’image,
* copiés automatiquement au premier lancement.

---

### Après build (recommandé)

```
darkmoon-settings/agents/
```

Avantages :

* modification sans rebuild,
* persistance,
* versioning externe.

---

## 7. Cycle de vie des agents

1. OpenCode démarre
2. Vérifie si les agents sont déjà présents
3. Seed initial si nécessaire
4. Chargement dynamique
5. Exécution à la demande

👉 Le seed ne se fait **qu’une seule fois**.

---

## 8. Ajouter un nouvel agent

### Méthode 1 — Après build (recommandée)

1. Créer un fichier `.md` dans :

   ```
   darkmoon-settings/agents/
   ```
2. Relancer Darkmoon
3. L’agent est disponible immédiatement

---

### Méthode 2 — Avant build

1. Ajouter l’agent dans :

   ```
   conf/agents/
   ```
2. Rebuild la stack
3. L’agent sera seedé automatiquement

---

## 9. Bonnes pratiques

* Un agent = un rôle clair
* Ne pas mélanger scan, reporting et correction
* Préférer plusieurs agents spécialisés
* Garder les règles strictes
* Tester progressivement

---

## 10. Résumé

Les agents Darkmoon :

* sont autonomes,
* auditables,
* extensibles,
* et sécurisés par design.

Ils constituent **le cerveau stratégique** de la plateforme.

---

➡️ Pour comprendre comment les agents exécutent des actions :
voir `docs/workflows.md`