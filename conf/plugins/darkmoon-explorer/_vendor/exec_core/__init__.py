"""exec_core: the shared executive-security core of Darkmoon (Community and Pro).

Pure Python standard library, no I/O, no import outside this package. The package is shipped byte-identically in
both editions; ``MANIFEST`` lists the SHA-256 of every module and the parity test of each edition recomputes it.
Licence: the licence of the repository that ships it (no per-file header, so the files stay byte-identical).

Modules: ``identity`` (finding identity, weakness class, asset key), ``stats`` (the one stats function),
``score`` (Cyber Score v1), ``project`` (project reference score), ``legend`` (shared vocabulary), ``actions``
(Prioritized Treatment Plan: actions, status machine, history), ``retest`` (retest verdicts with this identity),
``framework_catalogues`` + ``frameworks_assess`` (framework technical assessment: 4 states per control, applicability
from declared facts only), ``profile`` (application profile: validation, provenance, view), ``report_model`` (the one
report document, schema darkmoon-report/v2) + ``report_markdown`` (its Markdown rendering).
"""

VERSION = "1.3.0"

MANIFEST = {
    "actions.py": "8c9951cecfcaac8469d77247f4dcdc20c5a643d1811441f02ef27e2eab197456",
    "framework_catalogues.py": "f106db290849427c71d0885b600a57b64f21534944d88ec306ad5326eb9f3522",
    "frameworks_assess.py": "53faa0df35ddd1fb9177f9b844c58a1153c4a380d24f93590ba6d3d21ed7a617",
    "identity.py": "a76e274fd1079c53b683543f98ef411b89f288f518cb38c4e59a787ada7f326f",
    "legend.py": "84df25e47eda2e4616248a1a4afa4b09f07159ef7f66ce720168649f87163ea5",
    "profile.py": "113ed9f5994cbcb2baab2263f5af635000ccc808323c93aae66fedd8d56d7279",
    "project.py": "897ea6c825ad270ed3648cee4e452d74dae2d73b26b501ce58b8bf19bfe27b88",
    "report_markdown.py": "882a908f0f6976102094916e0d1ea49efa263daed2abd6f27388ab1d3124b9b4",
    "report_model.py": "7cf9550b5ae8e40e7b8e616b4276335aecdc8212346469704fe38481c965151d",
    "retest.py": "8430f27f3f8caf028f6c396faa430927c0efc74094746f921d69994cced66482",
    "score.py": "02a610b35777eb2b78ece837ef3a51f41a5b596111df08a3c2e6567d402331db",
    "stats.py": "42af8a28a0f30946551d2fac6cbfb20901071155376df2ddea5c207671b03c12",
}
