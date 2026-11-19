"""Catalogues of the framework technical assessment (data only, no logic).

Every entry is an identifier of the official text plus a one-line description written by Darkmoon of what a
technical test can observe. No normative text and no control title of a standard is reproduced: ISO/IEC 27001 is
cited by control identifier only; EU legal acts (reusable with attribution from EUR-Lex) by article reference only.

``classes`` of a control = the weakness classes (``identity.weakness_class`` + ``EXTRA_CLASS``) whose findings are
technical evidence for it; the same classes must have been exercised by a dispatched agent before « no weakness
observed in the tested scope » can be said. ``assessable: False`` = not assessable by a technical test, with ``why``.

Not shipped in v1: NIST CSF 2.0 (``EXCLUDED``). Kept unchanged and served elsewhere: ATT&CK, ATLAS, IEC 62443-3-3,
EBIOS RM views.
"""
from __future__ import annotations

CATALOGUE_VERSION = "darkmoon-framework-technical-catalogue/1"

# Weakness classes used below that ``identity`` does not produce on its own (category -> class).
EXTRA_CLASS = {
    "privilege_escalation": "privilege_escalation", "vertical_privilege_escalation": "privilege_escalation",
    "admin_privilege_escalation": "privilege_escalation",
    "source_code_disclosure": "source_code_exposure", "source_code_exposure": "source_code_exposure",
    "git_exposure": "source_code_exposure", "exposed_git": "source_code_exposure",
    "source_map_exposure": "source_code_exposure", "backup_file_exposure": "source_code_exposure",
    "exposed_service": "network_exposure", "network_exposure": "network_exposure", "open_port": "network_exposure",
    "open_ports": "network_exposure", "exposed_database": "network_exposure", "exposed_management_interface":
    "network_exposure",
    "prompt_injection": "ai_manipulation", "prompt_injection_direct": "ai_manipulation",
    "prompt_injection_indirect": "ai_manipulation", "llm_jailbreak": "ai_manipulation",
    "llm_improper_output_handling": "ai_manipulation", "llm_output_rendering_exfiltration": "ai_manipulation",
    "llm_excessive_agency": "ai_manipulation",
    "system_prompt_leakage": "ai_confidentiality", "llm_sensitive_information_disclosure": "ai_confidentiality",
    "llm_training_data_extraction": "ai_confidentiality", "llm_membership_inference": "ai_confidentiality",
    "llm_model_inversion": "ai_confidentiality", "llm_model_information_disclosure": "ai_confidentiality",
    "llm_unauthenticated_inference_api": "ai_exposure", "llm_unbounded_consumption": "ai_exposure",
}

# CWE number -> weakness class: used only when the category gives no mapped class.
CWE_CLASS = {
    "89": "sql_injection", "564": "sql_injection", "943": "nosql_injection",
    "79": "xss", "80": "xss", "83": "xss", "352": "csrf", "918": "ssrf", "611": "xxe", "776": "xxe",
    "77": "code_execution", "78": "code_execution", "94": "code_execution", "95": "code_execution",
    "502": "code_execution", "1336": "code_execution",
    "22": "file_access", "23": "file_access", "35": "file_access", "73": "file_access", "98": "file_access",
    "434": "file_upload",
    "284": "access_control", "285": "access_control", "639": "access_control", "862": "access_control",
    "863": "access_control", "269": "privilege_escalation", "915": "access_control", "425": "access_control",
    "287": "authentication", "288": "authentication", "306": "authentication", "307": "authentication",
    "521": "authentication", "798": "authentication", "1390": "authentication", "1391": "authentication",
    "1392": "authentication", "1393": "authentication",
    "384": "session", "613": "session", "614": "session", "1004": "session", "565": "session",
    "200": "information_disclosure", "201": "information_disclosure", "209": "information_disclosure",
    "215": "information_disclosure", "532": "information_disclosure", "538": "information_disclosure",
    "548": "information_disclosure", "359": "information_disclosure",
    "16": "configuration", "1021": "configuration", "942": "configuration", "693": "configuration",
    "319": "cryptography", "326": "cryptography", "327": "cryptography", "328": "cryptography",
    "916": "cryptography", "347": "cryptography", "321": "cryptography", "330": "cryptography",
    "1104": "vulnerable_component", "1395": "vulnerable_component", "937": "vulnerable_component",
    "601": "open_redirect", "400": "availability", "770": "availability", "799": "availability",
    "20": "input_validation", "840": "business_logic", "841": "business_logic",
    "540": "source_code_exposure", "527": "source_code_exposure",
    "1427": "ai_manipulation",
}

# ATT&CK technique (base id) -> weakness class: used only when neither the category nor the CWE gives one.
ATTACK_CLASS = {
    "T1110": "authentication", "T1078": "authentication", "T1550": "authentication", "T1556": "authentication",
    "T1552": "information_disclosure", "T1213": "information_disclosure", "T1005": "information_disclosure",
    "T1040": "cryptography", "T1557": "cryptography",
    "T1068": "privilege_escalation", "T1548": "privilege_escalation",
    "T1059": "code_execution", "T1203": "code_execution", "T1505": "code_execution",
    "T1539": "session", "T1185": "session",
    "T1498": "availability", "T1499": "availability",
    "T1046": "network_exposure", "T1133": "network_exposure",
}

# ISO/IEC 27001:2013 Annex A identifier -> ISO/IEC 27001:2022 Annex A identifier(s). Identifiers only (the
# correspondence published with ISO/IEC 27002:2022); agents often cite the 2013 numbering.
ISO_2013_TO_2022 = {
    "A.8.1.1": ["A.5.9"], "A.8.2.3": ["A.5.10"],
    "A.9.1.1": ["A.5.15"], "A.9.1.2": ["A.5.15"], "A.9.2.1": ["A.5.16"], "A.9.2.2": ["A.5.18"],
    "A.9.2.3": ["A.8.2"], "A.9.2.4": ["A.5.17"], "A.9.2.5": ["A.5.18"], "A.9.2.6": ["A.5.18"],
    "A.9.3.1": ["A.5.17"], "A.9.4.1": ["A.8.3"], "A.9.4.2": ["A.8.5"], "A.9.4.3": ["A.5.17"],
    "A.9.4.4": ["A.8.18"], "A.9.4.5": ["A.8.4"],
    "A.10.1.1": ["A.8.24"], "A.10.1.2": ["A.8.24"],
    "A.12.1.2": ["A.8.32"], "A.12.1.3": ["A.8.6"], "A.12.1.4": ["A.8.31"], "A.12.2.1": ["A.8.7"],
    "A.12.3.1": ["A.8.13"], "A.12.4.1": ["A.8.15"], "A.12.4.2": ["A.8.15"], "A.12.4.3": ["A.8.15"],
    "A.12.4.4": ["A.8.17"], "A.12.5.1": ["A.8.19"], "A.12.6.1": ["A.8.8"], "A.12.6.2": ["A.8.19"],
    "A.12.7.1": ["A.8.34"],
    "A.13.1.1": ["A.8.20"], "A.13.1.2": ["A.8.21"], "A.13.1.3": ["A.8.22"], "A.13.2.1": ["A.5.14"],
    "A.13.2.2": ["A.5.14"], "A.13.2.3": ["A.5.14"],
    "A.14.1.1": ["A.5.8", "A.8.26"], "A.14.1.2": ["A.8.26"], "A.14.1.3": ["A.8.26"], "A.14.2.1": ["A.8.25"],
    "A.14.2.2": ["A.8.32"], "A.14.2.3": ["A.8.32"], "A.14.2.4": ["A.8.32"], "A.14.2.5": ["A.8.27"],
    "A.14.2.6": ["A.8.31"], "A.14.2.7": ["A.8.30"], "A.14.2.8": ["A.8.29"], "A.14.2.9": ["A.8.29"],
    "A.14.3.1": ["A.8.33"], "A.17.2.1": ["A.8.14"], "A.18.1.4": ["A.5.34"], "A.18.2.3": ["A.5.36", "A.8.8"],
}

_WEB = ["sql_injection", "nosql_injection", "xss", "csrf", "ssrf", "xxe", "code_execution", "file_access",
        "file_upload", "open_redirect", "input_validation", "business_logic", "access_control", "authentication",
        "session", "information_disclosure", "configuration", "vulnerable_component", "source_code_exposure",
        "privilege_escalation"]
_BROWSER = ["xss", "csrf", "session", "authentication", "access_control", "information_disclosure",
            "configuration", "open_redirect", "input_validation"]
_PLATFORM = ["authentication", "access_control", "privilege_escalation", "configuration", "vulnerable_component",
             "information_disclosure", "network_exposure", "code_execution"]
_TRANSPORT = _PLATFORM + ["cryptography"]
_AI = ["ai_manipulation", "ai_confidentiality", "ai_exposure", "information_disclosure"]

# Dispatched agent -> weakness classes its instructions exercise. An agent not listed exercises nothing here
# (conservative: its silence never becomes « no weakness observed »). The orchestrator and generic sessions are absent.
AGENT_AREAS = {
    **{a: _WEB for a in ("aspnet", "drupal", "flask", "python-flask", "golang", "graphql", "joomla", "magento",
                         "moodle", "nest", "nodejs-express-angular", "php", "prestashop", "ruby", "springboot",
                         "wordpress", "business-platforms", "mobile")},
    "headless-browser": _BROWSER,
    "llm": _AI,
    **{a: _PLATFORM for a in ("ad", "ansible", "aws", "azure", "backup", "container-platform", "container-registry",
                              "docker", "entra-id", "firmware", "gcp", "github", "gitlab", "gitops",
                              "hashicorp-vault", "hypervisor", "jenkins", "kubernetes", "mdm", "messaging-cache",
                              "nosql-databases", "observability", "sql-databases", "storage", "terraform")},
    **{a: _TRANSPORT for a in ("edge-proxy", "email-infrastructure", "firewall-network", "pki-adcs", "sso-idp",
                               "vpn-remote-access")},
}

_INJECTION = ["sql_injection", "nosql_injection", "xss", "xxe", "code_execution", "file_access", "file_upload",
              "input_validation"]
_REQUEST_HANDLING = _INJECTION + ["csrf", "open_redirect", "business_logic"]
_CONF_INT = ["access_control", "privilege_escalation", "authentication", "session", "information_disclosure", "source_code_exposure",
             "sql_injection", "nosql_injection", "xss", "csrf", "ssrf", "xxe", "code_execution", "file_access",
             "file_upload"]
_DEV_MAINT = ["vulnerable_component", "configuration"] + _REQUEST_HANDLING + ["ssrf"]

ISO_NOT_SHOWN = ("Control identifiers only: the titles and text of ISO/IEC 27001 are not reproduced; the description is "
                 "Darkmoon's own summary of what a technical test can observe.")


def _c(cid, text, classes=None, why=None):
    if classes:
        return {"id": cid, "text": text, "assessable": True, "classes": list(classes)}
    return {"id": cid, "text": text, "assessable": False, "classes": [], "why": why or text}


_PROCESS = "An organisational process or document: a technical test of the application cannot observe it."

FRAMEWORKS = [
    {
        "framework": "iso27001",
        "label": "ISO/IEC 27001:2022 Annex A",
        "kind": "standard",
        "source": {"reference": "ISO/IEC 27001:2022, Annex A", "publisher": "ISO/IEC",
                   "url": "https://www.iso.org/standard/27001", "reuse": ISO_NOT_SHOWN},
        "scope_note": ("Annex A controls a technical test can produce evidence for, plus the technological controls "
                       "it cannot assess. Clauses 4 to 10 (the management system) are not assessed."),
        "applicability_field": "iso27001_isms_scope",
        "controls": [
            _c("A.5.14", "Data exchanged between the tested components and their clients travels over protected "
                         "channels.", ["cryptography"]),
            _c("A.5.15", "The application enforces who may reach which function or record (authorisation bypass, "
                         "object references, privilege escalation).", ["access_control", "privilege_escalation"]),
            _c("A.5.17", "Default, weak, guessable or exposed login secrets, and how they are handled by the tested "
                         "surface.", ["authentication"]),
            _c("A.5.18", "Granting, review and removal of user rights.", why=_PROCESS),
            _c("A.5.34", "Protection of personal data as a legal and organisational duty.",
               why="A legal and organisational obligation: exposure of personal data, when observed, is reported "
                   "under the technical controls (A.8.12) and GDPR art. 32."),
            _c("A.8.1", "Protection of end-user devices.",
               why="End-user devices are outside the scope of an application campaign."),
            _c("A.8.2", "Escalation from an ordinary account to administrative functions.", ["privilege_escalation"]),
            _c("A.8.3", "Reading or changing records of other users or tenants without authorisation.",
               ["access_control"]),
            _c("A.8.4", "Source code or repositories exposed through the tested surface (.git, backups, source "
                        "maps).", ["source_code_exposure"]),
            _c("A.8.5", "Login and session handling: authentication bypass, brute-force resistance, session "
                        "token handling.", ["authentication", "session"]),
            _c("A.8.6", "Resource exhaustion or missing rate limits observed (Darkmoon runs no load or "
                        "denial-of-service test).", ["availability"]),
            _c("A.8.7", "Anti-malware measures.", why="Anti-malware measures are not observable from the tested "
                                                        "surface."),
            _c("A.8.8", "Known-vulnerable or end-of-life components found on the tested surface (version evidence, "
                        "CVE references).", ["vulnerable_component"]),
            _c("A.8.9", "Insecure settings observed: debug modes, default pages, missing security headers, "
                        "permissive CORS, exposed admin consoles.", ["configuration"]),
            _c("A.8.10", "Deletion of data that is no longer needed.", why=_PROCESS),
            _c("A.8.11", "Masking of data by policy.",
               why="Whether data is masked by policy cannot be established by a test; data exposure observed is "
                   "reported under A.8.12."),
            _c("A.8.12", "Sensitive data returned or exposed to an unauthorised party (credentials, personal or "
                         "internal data in responses, errors or files).", ["information_disclosure"]),
            _c("A.8.13", "Copies of data kept for restore.", why="Backups and restores are not exercised by a security test."),
            _c("A.8.14", "Duplicate processing capacity.", why="Redundancy is not exercised by a security test."),
            _c("A.8.15", "Recording of security events.",
               why="Log content is not visible to the test; whether the test was recorded is not checked."),
            _c("A.8.16", "Detection of anomalous activity.",
               why="Whether the campaign was detected or alerted on is not recorded by Darkmoon."),
            _c("A.8.17", "Clocks set to a common time source.", why="Not observable from the tested surface."),
            _c("A.8.18", "Programs able to override system safeguards.", why="Not observable from the tested surface."),
            _c("A.8.19", "Software installation on production systems.", why=_PROCESS),
            _c("A.8.20", "Network services reachable from the tested position that should not be (exposed "
                         "management or data ports).", ["network_exposure"]),
            _c("A.8.21", "Agreements and service levels of network services.", why=_PROCESS),
            _c("A.8.22", "Reaching internal networks from the tested surface (server-side request forgery, "
                         "pivoting).", ["ssrf"]),
            _c("A.8.23", "Filtering of outbound web browsing by users.",
               why="Users' outbound browsing is outside the scope of an application campaign."),
            _c("A.8.24", "Weak or missing encryption observed: cleartext protocols, weak TLS, weak hashing, "
                         "unsigned or predictable tokens.", ["cryptography"]),
            _c("A.8.25", "Development lifecycle practices.", why=_PROCESS),
            _c("A.8.26", "How the application handles requests: injection, cross-site scripting, request forgery, "
                         "unsafe file handling, business-logic abuse.", _REQUEST_HANDLING),
            _c("A.8.27", "Architecture and engineering principles.",
               why="Design principles are not observable; their consequences appear as findings under A.8.26 / "
                   "A.8.28."),
            _c("A.8.28", "Flaws whose root cause is in the code: injection, unsafe deserialisation, path "
                         "traversal, missing output encoding.", _INJECTION),
            _c("A.8.29", "Testing during development and acceptance.",
               why="A development process: this campaign is an input to it, not an assessment of it."),
            _c("A.8.30", "Development by suppliers.", why=_PROCESS),
            _c("A.8.31", "Non-production environments kept apart from the live one.",
               why="Environments outside the tested scope are not visible to the test."),
            _c("A.8.32", "Change handling.", why=_PROCESS),
            _c("A.8.33", "Data used for testing.", why=_PROCESS),
            _c("A.8.34", "Safeguards for systems while they are being audited.",
               why="Applies to the test itself (rules of engagement), not assessed by it."),
        ],
    },
    {
        "framework": "gdpr",
        "label": "GDPR (EU) 2016/679, art. 32 and 25",
        "kind": "regulation",
        "source": {"reference": "Regulation (EU) 2016/679, articles 25 and 32", "celex": "32016R0679",
                   "url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
                   "reuse": "Article references only; descriptions are Darkmoon's own summary."},
        "scope_note": ("Only the technical side of the security of processing (art. 32) is covered. Breach "
                       "notification (art. 33-34), records, impact assessments and the other obligations are "
                       "organisational and not covered. An authorised test is not a personal data breach."),
        "applicability_field": "personal_data",
        "controls": [
            _c("Art.32(1)(a)", "Encryption observed on the tested surface (transport, stored secrets); "
                               "pseudonymisation is not observable.", ["cryptography"]),
            _c("Art.32(1)(b)-ci", "Confidentiality and integrity of the systems processing the data: weaknesses "
                                  "that let an attacker read or alter data or take over the system.", _CONF_INT),
            _c("Art.32(1)(b)-ar", "Availability and resilience: resource exhaustion observed (no load or "
                                  "denial-of-service test is run).", ["availability"]),
            _c("Art.32(1)(c)", "Restoring the data and services after an incident.",
               why="A restore capability is a process; it is not exercised by a security test."),
            _c("Art.32(1)(d)", "Recurring testing of the security measures.",
               why="A process: this campaign can be one of its inputs, it does not assess the process."),
            _c("Art.25", "Data protection by design and by default.",
               why="Design and default choices are a governance obligation; a technical test can only report "
                   "weaknesses, listed under art. 32."),
        ],
    },
    {
        "framework": "nis2",
        "label": "NIS2 Directive (EU) 2022/2555, art. 21(2)",
        "kind": "directive",
        "source": {"reference": "Directive (EU) 2022/2555, article 21(2)(a)-(j)", "celex": "32022L2555",
                   "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
                   "reuse": "Article references only; national transposition may differ and is not covered."},
        "scope_note": ("Only measures a test can produce technical evidence for. Whether the organisation is an "
                       "essential or important entity is declared by the organisation, never deduced."),
        "applicability_field": "nis2_entity_type",
        "controls": [
            _c("Art.21(2)(a)", "Risk analysis and security policies.", why=_PROCESS),
            _c("Art.21(2)(b)", "Incident handling.", why=_PROCESS),
            _c("Art.21(2)(c)", "Continuity, backups, recovery and crisis handling.",
               why=_PROCESS),
            _c("Art.21(2)(d)", "Security of suppliers and service providers.", why=_PROCESS),
            _c("Art.21(2)(e)", "Security of the systems as built and maintained: vulnerabilities found in the "
                               "tested scope (the vulnerability handling process itself is not assessed).", _DEV_MAINT),
            _c("Art.21(2)(f)", "Assessing whether the security measures work.",
               why="A process: this campaign can be one of its inputs, it does not assess it."),
            _c("Art.21(2)(g)", "Hygiene practices and security training of staff.", why=_PROCESS),
            _c("Art.21(2)(h)", "Cryptography and encryption weaknesses observed on the tested surface.",
               ["cryptography"]),
            _c("Art.21(2)(i)", "Authorisation enforcement observed on the tested surface (human resources security "
                               "and asset management are not assessed).", ["access_control", "privilege_escalation"]),
            _c("Art.21(2)(j)", "Authentication strength observed where the tested surface offers a login "
                               "(secured voice, video, text and emergency communications are not assessed).",
               ["authentication", "session"]),
        ],
    },
    {
        "framework": "ai_act",
        "label": "EU AI Act (EU) 2024/1689, art. 15",
        "kind": "regulation",
        "source": {"reference": "Regulation (EU) 2024/1689, article 15", "celex": "32024R1689",
                   "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                   "reuse": "Article references only; application dates are not stated here."},
        "scope_note": ("Applies to high-risk AI systems only. Whether a system is a high-risk AI system is declared "
                       "by the organisation; an AI component detected by the campaign never makes it one."),
        "applicability_field": "ai_risk_class",
        "controls": [
            _c("Art.15(1)", "Accuracy and consistent performance of the AI system.",
               why="Accuracy is measured against the intended purpose and declared metrics; out of scope of a "
                   "security test."),
            _c("Art.15(3)", "Accuracy figures published for users of the system.", why=_PROCESS),
            _c("Art.15(4)", "Resilience to errors, faults and inconsistencies, including feedback loops.",
               why="Not exercised by a security test."),
            _c("Art.15(5)-manipulation", "Attempts to alter use, outputs or behaviour through crafted inputs "
                                         "(prompt injection, jailbreak, evasion) and unsafe handling of model "
                                         "output or tool use.", ["ai_manipulation"]),
            _c("Art.15(5)-confidentiality", "Confidentiality attacks through the model: extraction of system "
                                            "instructions, training data, model information or sensitive data.",
               ["ai_confidentiality"]),
            _c("Art.15(5)-exposure", "Exploitation of the AI system's exposed interfaces (unauthenticated "
                                     "inference endpoint, unbounded resource consumption).", ["ai_exposure"]),
            _c("Art.15(5)-poisoning", "Manipulation of training data or pre-trained components.",
               why="Requires access to the training pipeline; not exercised by a black-box campaign."),
        ],
    },
]

EXCLUDED = [
    {"framework": "nist_csf_2", "label": "NIST Cybersecurity Framework 2.0",
     "why": ("Not in v1: its outcomes are mostly governance and process outcomes; a mapping from one campaign's "
             "findings would add a fifth view without new evidence. Reconsidered when requested by customers.")},
]

UNCHANGED_VIEWS = ["MITRE ATT&CK", "MITRE ATLAS", "IEC 62443-3-3", "EBIOS RM"]
