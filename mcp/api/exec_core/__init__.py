"""exec_core: the shared executive-security core of Darkmoon (Community and Pro).

Pure Python standard library, no I/O, no import outside this package. The package is shipped byte-identically in
both editions; ``MANIFEST`` lists the SHA-256 of every module and the parity test of each edition recomputes it.
Licence: the licence of the repository that ships it (no per-file header, so the files stay byte-identical).

Modules: ``identity`` (finding identity, weakness class, asset key), ``stats`` (the one stats function),
``score`` (Cyber Score v1), ``project`` (project reference score), ``legend`` (shared vocabulary), ``actions``
(Prioritized Treatment Plan: actions, status machine, history), ``retest`` (retest verdicts with this identity),
``framework_catalogues`` + ``frameworks_assess`` (framework technical assessment: 4 states per control, applicability
from declared facts only), ``profile`` (application profile: validation, provenance, view), ``report_model`` (the one
report document, schema darkmoon-report/v2) + ``report_markdown`` (its Markdown rendering), ``executive`` (the one
executive block of a campaign / project), ``static_text`` (Darkmoon's own published texts, kept out of the secret
redaction), ``maintenance`` (maintenance windows: the owner's launch policy and its evaluation; reads the host's
time-zone database through ``zoneinfo``), ``taxonomy`` (security event names and fields, secret and control-character
hygiene of log values).
"""

VERSION = "1.4.0"

MANIFEST = {
    "actions.py": "09a5f1cdeb53b8d667805a5b97e3686db5c5dc6904c72699b058aad46354e1da",
    "executive.py": "5460172efca2e821c30ebc8b06fef3746f9b9d28478f96c2f0fa622d52728fbd",
    "framework_catalogues.py": "f106db290849427c71d0885b600a57b64f21534944d88ec306ad5326eb9f3522",
    "frameworks_assess.py": "53faa0df35ddd1fb9177f9b844c58a1153c4a380d24f93590ba6d3d21ed7a617",
    "identity.py": "a76e274fd1079c53b683543f98ef411b89f288f518cb38c4e59a787ada7f326f",
    "legend.py": "8910d2c06a86c2b3addb1ca05b0225baf117e05681f45c63d1f9f7e283a6d41e",
    "maintenance.py": "738f9ca31d64f79621f7ee76d72357f7737cdfafab4550b7f7bdc69845325cac",
    "profile.py": "113ed9f5994cbcb2baab2263f5af635000ccc808323c93aae66fedd8d56d7279",
    "project.py": "897ea6c825ad270ed3648cee4e452d74dae2d73b26b501ce58b8bf19bfe27b88",
    "report_markdown.py": "882a908f0f6976102094916e0d1ea49efa263daed2abd6f27388ab1d3124b9b4",
    "report_model.py": "db63bbe47f4204fd47a62ad7e183d50a4601358bf7bc5471fa8f63e45f057106",
    "retest.py": "8430f27f3f8caf028f6c396faa430927c0efc74094746f921d69994cced66482",
    "score.py": "02a610b35777eb2b78ece837ef3a51f41a5b596111df08a3c2e6567d402331db",
    "static_text.py": "520a0d1bc0b1203f0d2c4c5aa76f9dded6c4b8af80018ae6b78855270cd2b5c2",
    "stats.py": "42af8a28a0f30946551d2fac6cbfb20901071155376df2ddea5c207671b03c12",
    "taxonomy.py": "a2ed23ce00494f80e7f26e162e19281f97c2a6fa3a47f1b1f00506241eb54b5a",
}
