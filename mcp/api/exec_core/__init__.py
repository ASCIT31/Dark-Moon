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
time-zone database through ``zoneinfo``; launch-target matching through ``ipaddress``), ``taxonomy`` (security event
names and fields, secret and control-character hygiene of log values, failed-login minimisation).

1.5.0 (cross-reviews of the executive V2): one treatment action per (asset, weakness class) with the migration of the
per-fix-item ids, retest coverage gate, risk acceptance with a named owner and an expiry, launch restrictions and a
digest of the coverage signals in the score gate, what holds the rating (next cap level, top classes), framework lines
gated by the declared applicability, test references without ISO 27001, proof attributed to the testing agent.
"""

VERSION = "1.5.0"

MANIFEST = {
    "actions.py": "9203d28185153ad3efa7cbf362d7be65be695b71e317f588e8eaad84886c8ff6",
    "executive.py": "049e4fdf497263446df8f2b9fbbb64139a947e413477d8a419be0c4f5cba1129",
    "framework_catalogues.py": "7ee0f2b3f95688f4091ba7725c925c95b1a1e5addf5b07d2d64e346872752cda",
    "frameworks_assess.py": "c40adeeb6fc7d81ee3ecb091999f62359ad28a94d6858c5b13dd48b571f19e39",
    "identity.py": "a76e274fd1079c53b683543f98ef411b89f288f518cb38c4e59a787ada7f326f",
    "legend.py": "58ab3dc5afc87dbd0d6d98c52b279b099bc9311619e10733097cc9a188fbdad9",
    "maintenance.py": "28a1fffca3c504a66652603c2da9353471dcb4e28141ef3fb6cc7c5a4cd21377",
    "profile.py": "4d0152d460be573fd09aef0026b49c7150f4e90c12021fd62a5c28bf0a5c04bc",
    "project.py": "897ea6c825ad270ed3648cee4e452d74dae2d73b26b501ce58b8bf19bfe27b88",
    "report_markdown.py": "7509e63bb754f552d794e5aa43b4c2dee04d1ca5ed934fff40d2fd131e7bd2da",
    "report_model.py": "f4c449c422e7d3d4e2c5ed4b66f9d2c9f4cc45fee227ff660f68d05da4ee0f4e",
    "retest.py": "8430f27f3f8caf028f6c396faa430927c0efc74094746f921d69994cced66482",
    "score.py": "c1f784c00919f791110f6f3eff6726b80a703b2d2fcf73de2f274269d3354869",
    "static_text.py": "520a0d1bc0b1203f0d2c4c5aa76f9dded6c4b8af80018ae6b78855270cd2b5c2",
    "stats.py": "42af8a28a0f30946551d2fac6cbfb20901071155376df2ddea5c207671b03c12",
    "taxonomy.py": "ab8f6907e469b07713a0f004f8cefd7f1cf82241dd5bca9b71fcc78774847103",
}
