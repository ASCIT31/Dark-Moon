# PR #42 reproduction lab

One command reproduces the regression this directory exists to pin, and shows
the same session against the current code.

```sh
BASELINE_IMAGE=ascit/opencode-darkmoon:latest tools/lab-tests/pr42-repro/reproduce.sh
```

Expected:

```
== BEFORE - ascit/opencode-darkmoon:latest ==
  refused                : 4/9
  filenames readable     : .htaccess

== AFTER - this checkout ==
  refused                : 0/9
  filenames readable     : index.php, robots.txt, .htaccess
```

## What it reproduces

Widening the default protection boundary to `URL`, `DOMAIN` and `PATH`
(issue #40, merged as PR #41) meant essentially **every** pentest command now
carries a placeholder, so every exfiltration rule in the gateway started firing
on legitimate work. PR #42 reported it from a VulnHub-style box: the agent could
no longer inspect a value it had discovered, and lost the ability to spot a
`~myfiles` directory it had found.

Two distinct failures show up here, and they fail differently:

**Refusal.** `_rehydrate()` refused any value carrying a shell metacharacter.
`?` is one, and the URL this lab redirects to has a query string, so
`curl URL_003` was refused outright. `cat PATH_001` was refused as a print sink,
although stdout is re-tokenized before the model sees it and therefore revealed
nothing in the first place.

**Silent corruption.** `_DOMAIN_RE` cannot tell `index.php` from
`acme-corp.com`, so once `DOMAIN` was on by default every filename in tool
output minted a placeholder. The agent stops being able to read an extension or
fuzz a name, and a later `nuclei -u DOMAIN_001` resolves to `index.php` instead
of the target. This one produces no error at all — in a live campaign the agent
simply requests the wrong URL and reports nothing wrong.

## How it works

Nothing here is hand-written. `reproduce.sh` builds the lab, runs **real**
`httpx`, `ffuf` and `curl` against it from inside the toolbox container, and
feeds the captured output through the privacy gateway. `compare.py` then does
what an agent does next with what it was handed: fetch the URLs it was shown,
read the files it discovered. The import path is whichever MCP tree the
container carries, so the same script measures the pre-fix image and this
checkout.

## The lab

A small Apache/PHP site shaped like the box in PR #42:

| Path | Why |
|---|---|
| `/` | 302 to `/index.php?page=home&lang=en` — a discovered URL with a query string |
| `/~myfiles/` | the `~`-prefixed directory from the PR, listable, holds `notes.txt` |
| `/includes/db_connect.php.bak` | a source backup with credentials in it |
| `/index.php?page=debug` | an error page naming absolute server paths |
| `/robots.txt` | points at the two directories |

The credentials in the lab are fake and local to it.

## Options

| Variable | Default | Effect |
|---|---|---|
| `TOOLBOX_CONTAINER` | `darkmoon` | Which toolbox container to scan from |
| `BASELINE_IMAGE` | *unset* | Image whose MCP carries the pre-fix code, for the A/B |
| `KEEP_LAB=1` | off | Leave the lab container running afterwards |
| `KEEP_CAPTURES=1` | off | Keep `captured/` so you can read the raw tool output |

Requires a running toolbox container; the lab joins its network.
