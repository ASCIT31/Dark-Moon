# ⚙️ Darkmoon — Installation & Setup

Ce document explique **comment installer, configurer et lancer Darkmoon**, pas à pas.

Aucune connaissance interne du projet n’est requise.

---

## 1. Prérequis

Avant de commencer, vous devez avoir :

- Docker
- Docker Compose
- Un accès à un fournisseur LLM (OpenRouter, Anthropic, OpenAI…)

---

## 2. Structure générale du projet

Darkmoon repose sur **Docker** et **Docker Compose**.

Les composants importants sont :
- un conteneur **OpenCode** (IA + agents),
- un conteneur **Darkmoon Toolbox** (outils de pentest),
- des **volumes partagés** pour la configuration.

---

## 3. Configuration des variables d'environement dans le docker compose

Le docker compose est **le point d’entrée de toute la configuration IA**.

### Exemple de variable d'environement 

```env
    environment:
      # 🔽 TEST runtime variables LLM conf
      - OPENROUTER_PROVIDER=openai
      - OPENCODE_MODEL=gpt-4o
      - OPENROUTER_API_KEY=sk-svcacct-xxx
````

### Rôle des variables

| Variable              | Rôle                      |
| --------------------- | ------------------------- |
| `OPENROUTER_PROVIDER` | Fournisseur du modèle LLM |
| `OPENCODE_MODEL`      | Modèle exact utilisé      |
| `OPENROUTER_API_KEY`  | Clé API du fournisseur    |

👉 Aucun secret n’est stocké dans l’image Docker.

---

## 4. Génération automatique des fichiers OpenCode

Au premier lancement, Darkmoon :

1. lit les variables`,
2. génère automatiquement :

   * `opencode.json`,
   * `auth.json`,
3. configure l’agent principal,
4. initialise OpenCode.

Tout cela est fait par le script :

```
conf/apply-settings.sh
```

👉 Vous **n’avez rien à générer manuellement**.

Vous pouvez faire le choix de ne pas remplir les variables , auxquel cas, le modèle d'opencode `opencode/big-pickle` par défaut sera exécuté

---

## 5. Volumes et persistance

Les fichiers de configuration sont persistés via des volumes Docker.

### Volumes importants

```yaml
- ./darkmoon-settings:/root/.config/opencode/:rw
- ./darkmoon-settings:/root/.local/share/opencode/:rw
- ./darkmoon-settings/agents:/root/.opencode/agents/:rw
```

### Ce que cela permet

* Modifier la configuration **sans rebuild**
* Ajouter ou modifier des agents IA
* Conserver les logs et l’état OpenCode

---

## 6. Build et lancement de Darkmoon

### Construction des images

```bash
docker compose build
```

### Lancement de la stack

```bash
docker compose up -d
```

👉 Le premier lancement peut prendre du temps (build des images).

---

## 7. Lancer Darkmoon (CLI utilisateur)

Un wrapper est fourni : `darkmoon.sh`.

### Rendre le wrapper exécutable

```bash
chmod +x darkmoon.sh
```

### Installer globalement (optionnel)

```bash
sudo cp darkmoon.sh /usr/local/bin/darkmoon
```

### Lancer Darkmoon

```bash
darkmoon
```

Ou avec une commande directe :

```bash
darkmoon "exécute un scan de vulnérabilité sur example.com"
```

---

## 8. Accès direct au conteneur (debug)

Il est possible d’entrer directement dans le conteneur OpenCode :

```bash
docker exec -ti opencode bash
```

Cela permet :

* d’inspecter les fichiers,
* de modifier des agents,
* de tester OpenCode directement.

---

## 9. Où modifier quoi (récapitulatif)

| Action                       | Où                                |
| ---------------------------- | --------------------------------- |
| Modifier le modèle LLM       | `.env`                            |
| Modifier `opencode.json`     | `darkmoon-settings/opencode.json` |
| Modifier `auth.json`         | `darkmoon-settings/auth.json`     |
| Ajouter un agent             | `darkmoon-settings/agents/`       |
| Ajouter un agent avant build | `conf/agents/`                    |

---

## 10. Résumé rapide

* `.env` → configuration IA
* `docker compose up -d` → lancement
* `darkmoon` → utilisation
* Volumes → persistance & modification à chaud

---

➡️ Pour les problèmes de build ou de rebuild :
voir `docs/rebuild-and-troubleshooting.md`
