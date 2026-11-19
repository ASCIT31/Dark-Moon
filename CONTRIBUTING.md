# 🤝 Contributing to Darkmoon

Thank you for your interest in Darkmoon.

This document defines **the contribution guidelines** to ensure:

- quality,
- security,
- maintainability.

## 1. Project Philosophy

Darkmoon is:

- open-source,
- security-oriented,
- designed to be auditable.

Any contribution must:

- be readable,
- be justified,
- respect the existing architecture.

## 2. Accepted Contribution Types

- new pentesting tools
- new MCP workflows
- agent improvements
- documentation
- security fixes

## 3. Adding a Tool

### Where to Add It?

| Tool Type | File            |
| --------- | --------------- |
| Binary    | `setup.sh`      |
| Python    | `setup_py.sh`   |
| Ruby      | `setup_ruby.sh` |

Rules:

- one tool = one clear block
- mandatory validation
- clean installation

## 4. Adding an MCP Workflow

1. Copy `mcp/src/tools/workflows/TEMPLATE.py`
2. Implement coherent logic
3. Structure the outputs
4. Test locally
5. Document it

📄 See `mcp/WORKFLOW_GUIDE.md`

## 5. Adding or Modifying an Agent

- agents = Markdown files
- strict rules
- MCP mandatory
- no dangerous logic

👉 An agent is a **strategy**, not a script.

## 6. Best Practices

- do not break compatibility
- no “quick hacks”
- prioritize security over performance
- document every decision

## 7. Code of Conduct

- respect
- clarity
- transparency
- security before ego

## 8. Licensing of Contributions and CLA

Darkmoon Community is distributed under the GNU Affero General Public License v3.0 (AGPL-3.0-only); by opening a pull
request you agree that your contribution is licensed under it.

A [Contributor License Agreement](CLA.md) (and a [Corporate CLA](CLA-CORPORATE.md) for organisations) is being
prepared. **Both are drafts under legal review and cannot be signed yet**; once the reviewed version is published,
the CLA bot will ask each contributor to sign it once by a comment on their pull request. Contributions made before
the switch to the AGPL-3.0 stay under the GPL-3.0: see [LICENSING.md](LICENSING.md).

---

## 9. Conclusion

Darkmoon is a serious project.

If you contribute:

- do it cleanly,
- do it clearly,
- do it responsibly.

Thank you 🙏
