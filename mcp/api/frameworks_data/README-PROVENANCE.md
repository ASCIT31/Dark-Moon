# frameworks_data — provenance

Reduced extracts of official framework data, generated on 2026-11-03. On a version bump they are regenerated from the
new official release and the tests fail on any crosswalk ID absent from the new version.

| File | Official source | sha256 of the source | Licence |
|---|---|---|---|
| ../vendor/mitre_attack/attack-enterprise-20.0.min.json | https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-20.0.json | 81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352 | MITRE ATT&CK Terms of Use, text in ../vendor/mitre_attack/LICENSE.txt (© The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation) |
| atlas-2026.10.min.json | https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.10.yaml | ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d | Apache-2.0, Copyright 2021-2026 MITRE, text in LICENSE-ATLAS.txt (atlas-data has no NOTICE file: 404 on 2026-11-03) |
| (lineage input) ATLAS-2026.09.yaml | https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml | 935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688 | Apache-2.0 |
| llm-atlas-crosswalk.json | Darkmoon, curated (NOT official). Cites OWASP Top 10 for LLM Applications 2025 IDs only (CC BY-SA 4.0, attribution: OWASP Foundation); no OWASP text reproduced | — | Darkmoon |
| iec62443-3-3-crosswalk.json | Darkmoon, curated (NOT official). IEC 62443-3-3 numbering only; the summaries are Darkmoon's own wording, no IEC/ISA text or title | — | Darkmoon |

Modifications: the MITRE files are reduced to IDs, names, tactics, revoked-by relations and removed IDs. No ISO text or
ISO title is embedded anywhere.

## ATT&CK: one directory, one licence

The ATT&CK extract lives in **`api/vendor/mitre_attack/`**, which holds the only ATT&CK `LICENSE.txt` and `NOTICE`
(the `license` field of the extract points to `api/vendor/mitre_attack/LICENSE.txt`).

## Integration rules

- Show only the ISO control ID and the title the agent wrote; never embed an ISO title or ISO text.
- OWASP: IDs and short titles only, with attribution; no description is reproduced.
- Every framework view carries the version and the attribution (`frameworks.framework_licences()`).
