# 🌑 Darkmoon — Agentic AI Pentest Platform

Darkmoon est une **plateforme de pentest agentique basée sur l’IA**, conçue pour exécuter **de vrais tests d’intrusion**, de bout en bout, en combinant :

- des **agents IA autonomes**,
- un **serveur MCP sécurisé**,
- une **toolbox Docker industrielle**,
- et un **orchestrateur LLM agnostique**.

> Une phrase → une campagne de pentest complète.

---

## 🚀 Pourquoi Darkmoon existe

Les outils de sécurité sont :
- fragmentés,
- manuels,
- peu corrélés,
- difficiles à industrialiser.

Darkmoon répond à ce problème en proposant :
- une **orchestration agentique**,
- une **exécution réelle des outils**,
- une **corrélation automatique des résultats**,
- une **architecture reproductible et extensible**.

Darkmoon **n’est pas** :
- un simple scanner,
- un wrapper d’outils,
- un chatbot qui lance des commandes.

Darkmoon est une **chaîne d’exécution offensive complète**, pilotée par l’IA.

---

## 🧠 Vue d’ensemble (simple)

1. L’utilisateur écrit un objectif :
   > *“Exécute un scan de vulnérabilité sur example.com”*

2. Un **agent IA** comprend la mission.
3. Il appelle le **serveur MCP Darkmoon**.
4. Le MCP exécute **de vrais outils** dans la toolbox Docker.
5. Les résultats sont analysés.
6. L’agent **enchaîne, exploite, itère**.

---

## 🧩 Composants principaux

| Composant | Rôle |
|---------|------|
| **OpenCode** | Orchestrateur IA / agents |
| **Agents Markdown** | Logique offensive autonome |
| **MCP Darkmoon (FastMCP)** | Pont IA ↔ outils |
| **Toolbox Docker** | Outils de pentest réels |
| **Docker & volumes** | Isolation et persistance |

---

## ⚡ Démarrage rapide

```bash
docker compose build --no-cache
docker compose up -d
````

Puis :

```bash
chmod +x ./darkmoon.sh
./darkmoon.sh
```

ou

```bash
sudo mv ./darkmoon.sh /usr/local/bin/darkmoon
sudo chmod 755 /usr/local/bin/darkmoon
darkmoon
```

### 🧪 Lancer un test d’intrusion complet avec un agent IA

Darkmoon utilise **OpenCode** pour orchestrer des **agents IA spécialisés**.
Les agents sont sélectionnables **directement dans l’interface** via `@`.

---

### 🔹 Principe

* Chaque agent représente une **stratégie de pentest autonome**
* Les agents sont définis en **Markdown**
* Ils utilisent **exclusivement le MCP Darkmoon** pour exécuter de vrais outils
* L’orchestration est **automatique, sans interaction humaine**

---

### 🔹 Lancer Darkmoon (mode interactif)

```bash
darkmoon
```

Cela ouvre l’interface OpenCode (TUI ou CLI selon le contexte).

---

### 🔹 Sélectionner un agent avec `@`

Dans l’interface OpenCode, tapez :

```
/agent
```

➡️ OpenCode affiche la **liste des agents disponibles**
(ex: `pentest-ad`, `pentest-web`, etc.)

Sélectionnez :

```
@pentest-ad
```

---

### 🔹 Exemple : lancer un pentest de bout en bout

Une fois l’agent sélectionné, saisissez simplement :

#### Pour Juice Shop

```
lance un pentest sur http://juice-shop:3000 afin d’identifier des vulnérabilités,
et réalise des attaques web telles que XSS, injection SQL, CSRF, XXE, contournement de l’authentification, etc.
Tu peux extraire des informations sensibles. Utilise darkmoon mcp pour l’outillage offensif
et mcp darkmoon (using lightpanda) pour naviguer sur la cible.

pour cela, 

tu dois d'abord découvrir les endpoint API avec katana et httpx avec ces commandes:

httpx -mc 200,302 
katana -aff -fx -jc -jsl -xhr -kf all -depth 5

et ensuite une fois qur tu as les endpoint,tu vas tenter avec les endpoint trouvé de faire des attaques web telles que XSS, injection SQL, CSRF, XXE, contournement de l’authentification 

obligatoirement 

en utilisant la tolbox du MCP de darkmoon, décrit dans l'agent de pentest web

ps: ne lance pas de scan de vuln, cette app n'en a pas
```

#### Pour DVGA

```
ance un pentest sur l'application graphql http://dvga:5013 afin d’identifier des vulnérabilités,
et réalise des attaques web telles que XSS, injection SQL, CSRF, XXE, contournement de l’authentification, etc.
Tu peux extraire des informations sensibles. Utilise darkmoon mcp pour l’outillage offensif
et mcp darkmoon (using lightpanda) pour naviguer sur la cible.

pour cela, 

tu dois d'abord découvrir les endpoint API avec katana et httpx avec ces commandes:

httpx -mc 200,302 
katana -aff -fx -jc -jsl -xhr -kf all -depth 5

et ensuite une fois qur tu as les endpoint,tu vas tenter avec les endpoint trouvé de faire des attaques web telles que XSS, injection SQL, CSRF, XXE, contournement de l’authentification 

voici le type d'attaque que tu dois obligatoirement réaliser (chainé, orchestré entres eux avec une logique de dépendance et de maillage d'attaque classique):

-Introspection GraphQL (schema, type, types/fields/args).
-Users loot (users { id username password/... }).
-Pastes loot (pastes { id title content owner {...} }).
-Audit logs (audits { id gqloperation gqlquery timestamp ... }).
-XSS via mutations (createPaste/uploadPaste/editPaste/createUser + lecture du payload).
-File/SSRF/LFI (importPaste, uploadPaste, chemins/hosts dangereux).
-SQLi / logique sur recherches/filtres (search, filter, etc.).
-JWT/Auth abuse (login, me(token), tokens forgés/invalides).
-System* (systemDiagnostics, systemDebug, systemHealth, systemUpdate).
-Logic/Authorization abuse (IDOR, mass-assignment, readAndBurn, owner/pastes).
-DoS / complexité GraphQL (deep nesting, alias flooding, duplication).
-RCE-like persistants (payloads shell stockés dans pastes).
-Subscriptions / temps réel (/subscriptions, type Subscription).
-Endpoints complémentaires (/solutions, /graphql, /graphiql, /audit, REST, etc.).

obligatoirement 

Tu exploites en priorité : 1) /graphql (+ éventuellement /graphiql, /subscriptions). 2) Endpoints découverts dans <recon> (REST, /solutions, /audit, etc.).
Tu ne fais pas de bruteforce bourrin (login limité, tests intelligents).
en utilisant la tolbox du MCP de darkmoon, décrit dans l'agent de pentest web

ps: ne lance pas de scan de vuln, cette app n'en a pas
```
---

### 🔹 Ce qu’il se passe automatiquement

Sans aucune autre action de votre part, l’agent va :

1. Construire une **cartographie de la cible**
2. Lancer des **phases de reconnaissance**
3. Exécuter des **scans de vulnérabilités**
4. Enchaîner des **workflows MCP** (nuclei, recon, crawling, etc.)
5. Exploiter si des failles sont détectées
6. Corréler les résultats
7. Itérer jusqu’à épuisement des vecteurs

👉 **Aucune confirmation demandée**
👉 **Aucune commande à écrire**
👉 **Aucune orchestration manuelle**

---

### 🔹 Exemple de prompts équivalents

```text
exécute un scan de vulnérabilité complet sur dark-moon.org
```

```text
réalise un pentest web approfondi sur https://dark-moon.org
```

```text
analyse la surface d’attaque publique du domaine dark-moon.org
```

L’agent choisira **lui-même** :

* les workflows MCP à appeler,
* les outils à exécuter,
* l’ordre et la profondeur des attaques.

---

### 🔹 Vérifier l’état de la toolbox (optionnel)

Avant ou pendant une mission, vous pouvez demander :

```
exécute la fonction health_check
```

L’agent (ou OpenCode) appellera le MCP pour :

* vérifier que la toolbox est prête,
* lister les outils disponibles,
* confirmer l’état global du système.

---

### 🔹 Important à comprendre

* Le langage utilisé est **du langage naturel**
* Il n’y a **pas de syntaxe spéciale**
* L’IA comprend l’intention, pas une commande

👉 Vous **décrivez un objectif**, pas une procédure.

---

### 🧠 Résumé rapide

| Action                     | Résultat                    |
| -------------------------- | --------------------------- |
| `darkmoon`                 | Lance OpenCode              |
| `@`                        | Liste les agents            |
| `@FastMCP Pentest Agent …` | Lance un pentest complet    |
| Langage naturel            | Orchestration automatique   |
| MCP                        | Exécution réelle des outils |


---

## 📁 Documentation complète

👉 Toute la documentation détaillée est dans `/docs`.

* [`docs/setup.md`](docs/setup.md)
  Installation, configuration, lancement

* [`docs/architecture.md`](docs/architecture.md)
  Architecture détaillée + diagrammes Mermaid

* [`docs/agents.md`](docs/agents.md)
  Agents IA, règles, exemples

* [`docs/mcp.md`](docs/mcp.md)
  MCP Darkmoon, outils, workflows

* [`docs/workflows.md`](docs/workflows.md)
  Création et exécution des workflows

* [`docs/rebuild-and-troubleshooting.md`](docs/rebuild-and-troubleshooting.md)
  Rebuild propre, erreurs Docker, WSL

* [`docs/security-threat-model.md`](docs/security-threat-model.md)
  Threat model de Darkmoon lui-même

* [`docs/contributing.md`](docs/contributing.md)
  Guide contributeur

* [`docs/toolbox.md`](docs/toolbox.md)
  Documentation de la toolbox de Darkmoon

---

## 🔐 Sécurité & philosophie

* Aucun secret hardcodé
* Isolation Docker stricte
* Outils exécutés uniquement via MCP
* LLM **agnostique**
* Agents **auditables en Markdown**

---

## 🧠 À qui s’adresse Darkmoon

* Pentesters
* Red Team
* RSSI / CTO
* Chercheurs sécurité
* Équipes DevSecOps

---

## 🌓 Conclusion

Darkmoon est une **plateforme offensive agentique**, conçue pour :

* penser comme un pentester,
* agir comme une toolbox industrielle,
* évoluer comme un framework IA moderne.

Ce n’est pas une promesse marketing.
C’est une **architecture complète, observable et extensible**.