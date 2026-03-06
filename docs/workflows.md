# Darkmoon --- MCP Workflows

This document explains **what MCP workflows are**, how they work, and
how to create new ones.

Target audience:

- developers
- advanced pentesters
- contributors

## 1. What is an MCP Workflow?

A workflow is:

- a **Python module**,
- exposed by the MCP,
- that encapsulates a **coherent sequence of actions**,
- executed inside the Docker toolbox.

> [!NOTE]
> A workflow = a complete operational task.

## 2. Where Workflows Live

Workflows are located in:

```
mcp/src/tools/workflows/
```

Examples:

- `port_scan.py`
- `vulnerability_scan.py`
- `web_crawler.py`

## 3. Dynamic Discovery

At startup:

- the MCP automatically scans workflows,
- exposes their methods,
- makes them accessible to the AI.

> [!TIP]
> No manual registration required.

## 4. Workflow Structure

Each workflow:

- inherits from `BaseWorkflow`,
- defines one or more methods,
- manages its timeouts,
- structures its results.

## 5. Example: Vulnerability Scan

The `VulnerabilityScanWorkflow`:

- creates a dedicated workspace,
- runs Nuclei,
- parses JSON results,
- correlates findings by severity,
- returns a structured summary.

> [!IMPORTANT]
> This is not just a tool call. It is **complete operational logic**.

## 6. Called by an Agent

An agent can call:

```
run_workflow("vulnerability_scan", "scan_vulnerabilities", {...})
```

The agent:

- chooses the appropriate workflow,
- decides when to execute it,
- interprets the results.

## 7. Advantages of Workflows

- reusable
- testable
- auditable
- safer than raw command execution

## 8. Creating a New Workflow

1.  Copy `TEMPLATE.py`
2.  Implement the logic
3.  Respect the structure
4.  Test locally
5.  Restart the MCP

> [!TIP]
> For detailed guide, see [WORKFLOW_GUIDE.md](/mcp/WORKFLOW_GUIDE.md)

## 9. Best Practices

- One workflow = one mission
- Avoid mixing too many responsibilities
- Always structure outputs
- Handle timeouts properly

## 10. Summary

Workflows:

- are the operational backbone of Darkmoon,
- encapsulate offensive logic,
- secure the execution of tools.

> [!NOTE]
> To understand the MCP itself, see [mcp.md](/docs/mcp.md)
