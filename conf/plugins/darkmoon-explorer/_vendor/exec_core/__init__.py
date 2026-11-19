"""exec_core: the shared executive-security core of Darkmoon (Community and Pro).

Pure Python standard library, no I/O, no import outside this package. The package is shipped byte-identically in
both editions; ``MANIFEST`` lists the SHA-256 of every module and the parity test of each edition recomputes it.
Licence: the licence of the repository that ships it (no per-file header, so the files stay byte-identical).

Modules: ``identity`` (finding identity, weakness class, asset key), ``stats`` (the one stats function),
``score`` (Cyber Score v1), ``project`` (project reference score), ``legend`` (shared vocabulary).
"""

VERSION = "1.0.0"

MANIFEST = {
    "identity.py": "715f2ca4bcc24aaff3b5fbd86809b144d6b6406c1c5ebb9c298b843888180413",
    "legend.py": "84df25e47eda2e4616248a1a4afa4b09f07159ef7f66ce720168649f87163ea5",
    "project.py": "face60537963bbede0540fb0cd6a14e54531e6005460d5e46b9e594485fe393d",
    "score.py": "28de18c3b2242976a50a75accc206f337224e1f71c582970711e97993888db58",
    "stats.py": "42af8a28a0f30946551d2fac6cbfb20901071155376df2ddea5c207671b03c12",
}
