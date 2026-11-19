# Licensing

## Darkmoon Community: AGPL-3.0

Darkmoon Community (this repository: CLI, TUI and Terminal Explorer, agents, toolbox, MCP server and orchestrator,
attack-path engine, reports) is free software licensed under the
[GNU Affero General Public License v3.0](LICENSE) (SPDX: `AGPL-3.0-only`), from the first release published under
that license onwards.

In short (the [LICENSE](LICENSE) text is what applies):

- **Use it, study it, change it, share it.** Running Darkmoon, internally or for your own assessments, is free.
- **If you distribute it**, modified or not, you distribute the corresponding source under the AGPL-3.0.
- **If you run a modified version as a network service** (users interact with it remotely), you must offer those
  users the corresponding source of your modified version (AGPL-3.0, section 13).
- The AGPL-3.0 does not restrict who may use the software or for what; it requires reciprocity.

## What stays under the GPL-3.0

**Earlier releases.** Every version of Darkmoon Community published up to commit `edfe9cb` (27 October 2026) was
licensed under the [GNU General Public License v3.0](LICENSES/GPL-3.0.txt). Those versions stay available under that
license; the change does not withdraw any right already granted.

**Earlier outside contributions.** The contributions listed below were made by people outside ASC before the switch,
under the GNU General Public License v3.0. They stay under that license: ASC does not relicense them. They remain in
this repository, combined with the AGPL-3.0 code, as section 13 of the GNU GPL v3.0 and section 13 of the GNU AGPL v3.0
expressly allow. In practice:

- the repository as a whole is distributed under the AGPL-3.0, and anyone who complies with the AGPL-3.0 also complies
  with the GPL-3.0 for these contributions;
- these contributions, taken on their own (for example by `git blame` or from the commits below), can still be used
  under the GPL-3.0;
- they are not included in ASC's commercial licenses unless their author agrees, for example by signing the
  [CLA](CLA.md) with the « earlier contributions » sentence, or until ASC replaces them with its own code.

| Contributor | Contribution (pull request or commits) | Files where it remains |
|---|---|---|
| luojiyin ([@luojiyin1987](https://github.com/luojiyin1987)) | #41 workflow privacy parity | `mcp/src/privacy/gateway.py`, `mcp/src/server.py`, `mcp/src/tools/workflows/list_workflows.py`, `mcp/tests/test_workflow_privacy.py` |
| Tudor-Andrei Oprea | #42 per-session privacy override | `mcp/src/privacy/gateway.py`, `mcp/src/privacy/vault.py`, `mcp/src/server.py`, `mcp/tests/test_session_privacy.py` |
| Raj Gahoi ([@RajGahoi](https://github.com/RajGahoi)) | #52 MCP workflow validator | `mcp/test_workflow.py`, `mcp/tests/test_workflow_validator.py` |
| Emre K ([@kocaemre](https://github.com/kocaemre)) | #51 workflow allowlist sync | `mcp/src/tools/core/allowlist.py`, `mcp/src/tools/core/executor.py`, `mcp/src/tools/workflows/base.py`, `mcp/tests/test_tool_whitelist.py` |
| Maxi ([@maximilianfeix](https://github.com/maximilianfeix)) | #53 port-scan workflow tests | `mcp/tests/test_port_scan_workflow.py` |
| obzennn ([@obzennn](https://github.com/obzennn)) | #26 arm64 support | `Dockerfile`, `install.sh`, `setup.sh` |
| Pixis ([@Hackndo](https://github.com/Hackndo)) | #27 settings fix | `conf/apply-settings.sh` |
| Amael Heiligtag ([@AppSecAmael](https://github.com/AppSecAmael)) | #25 report location | `mcp/api/json_storage.py` |
| CM ([@EveX1](https://github.com/EveX1)) | #15 documentation | `docs/full.md` |
| Florian Cardinal ([@Tracks12](https://github.com/Tracks12)) | documentation and repository files (March 2026) | `CONTRIBUTING.md`, `README.md`, `.gitignore`, `mcp/.gitignore` |

If you are one of these contributors and want your contribution under the AGPL-3.0 (and the CLA) too, or removed,
open an issue or sign the [CLA](CLA.md) with the « earlier contributions » sentence.

## Contributing from now on

New contributions are accepted under the AGPL-3.0 and require the
[Contributor License Agreement](CLA.md) (individuals) and, when you contribute for an organisation, the
[Corporate CLA](CLA-CORPORATE.md). The CLA lets ASC also offer Darkmoon under commercial licenses; in exchange ASC
commits that every contribution it includes in the open-source edition stays available under an open-source license.

## Commercial licensing

Darkmoon Pro is a separate commercial product with its own license. Organisations that want to embed or redistribute
Darkmoon without the obligations of the AGPL-3.0 can ask ASC (ASC-IT) for a commercial license, through
[dark-moon.org](https://dark-moon.org), within the limits of the rights ASC holds (the contributions listed above are
excluded unless their authors agree).

## Trademarks

The licenses cover the code, not the Darkmoon name and logos. Forks and services built on this code must not present
themselves as the official Darkmoon product.

## License texts

- [LICENSE](LICENSE) — GNU Affero General Public License v3.0 (also in [LICENSES/AGPL-3.0.txt](LICENSES/AGPL-3.0.txt))
- [LICENSES/GPL-3.0.txt](LICENSES/GPL-3.0.txt) — GNU General Public License v3.0 (earlier releases and earlier outside
  contributions)
