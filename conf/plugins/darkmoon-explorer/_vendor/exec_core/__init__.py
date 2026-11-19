"""exec_core: the shared executive-security core of Darkmoon (Community and Pro).

Pure Python standard library, no I/O, no import outside this package. The package is shipped byte-identically in
both editions; ``MANIFEST`` lists the SHA-256 of every module and the parity test of each edition recomputes it.
Licence: the licence of the repository that ships it (no per-file header, so the files stay byte-identical).

Modules: ``identity`` (finding identity, weakness class, asset key), ``stats`` (the one stats function),
``score`` (Cyber Score v1), ``project`` (project reference score), ``legend`` (shared vocabulary), ``actions``
(Prioritized Treatment Plan: actions, status machine, history), ``retest`` (retest verdicts with this identity).
"""

VERSION = "1.1.0"

MANIFEST = {
    "actions.py": "7429e6c0df78c0e6510ab00055277df8d884fe1b2c5bb5ba2d8d9af557bf5753",
    "identity.py": "a76e274fd1079c53b683543f98ef411b89f288f518cb38c4e59a787ada7f326f",
    "legend.py": "84df25e47eda2e4616248a1a4afa4b09f07159ef7f66ce720168649f87163ea5",
    "project.py": "897ea6c825ad270ed3648cee4e452d74dae2d73b26b501ce58b8bf19bfe27b88",
    "retest.py": "8430f27f3f8caf028f6c396faa430927c0efc74094746f921d69994cced66482",
    "score.py": "02a610b35777eb2b78ece837ef3a51f41a5b596111df08a3c2e6567d402331db",
    "stats.py": "42af8a28a0f30946551d2fac6cbfb20901071155376df2ddea5c207671b03c12",
}
