# Maintenance windows (Community)

A project's **maintenance policy** says when active testing may start on it. Community uses the same model and
evaluation as Pro (`mcp/api/exec_core/maintenance.py`) but **only warns**: it never blocks a launch.

## Writing the policy

The owner writes it by hand, in a local file (no MCP tool writes it, the model never reads it):

```
~/.local/share/opencode/policies/<project_id>.json      (or $DARKMOON_DATA_DIR/policies/)
```

```json
{
  "schema_version": "darkmoon-maintenance-policy/1",
  "project_id": "<project_id>",
  "timezone": "Europe/Paris",
  "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "22:00", "end": "06:00"}],
  "blackouts": [{"start": "2026-12-24", "end": "2027-01-02", "label": "Year-end freeze"}],
  "max_duration_minutes": 360
}
```

Fields and rules: see the Pro page (`windows` are local wall-clock times in `timezone`, `end` before `start` runs past
midnight, `24:00` is midnight, blackout dates block windows too, `intrusive_only`, `max_duration_minutes`). The file is
validated on every read; a file that cannot be read, has an unknown field, a foreign `project_id` or an unknown time
zone is never ignored silently: every launch gets the warning until it is fixed.

## What happens at launch

When the orchestrator initialises a campaign (`dashboard_init_campaign`), the server evaluates the project's policy:

- outside it, the MCP server writes a WARNING line on its log and a `campaign.launch` / `warning` security event, and
  records the evaluation on the campaign (`maintenance_check`); the campaign goes on;
- the tool's answer to the model is unchanged (no instruction is added to the agent).

## Reading it

- Terminal explorer: `W` (or the palette entry « Maintenance windows ») on a project; adapter command
  `darkmoon_explore.py maintenance <project_id>`.
- From a script or a pipeline (inside the Darkmoon container, from `mcp/`):
  `python3 -m api.maintenance_local check <project_id> [--kind full] [--duration 120] [--at 2026-11-20T21:00:00Z]`
  prints the evaluation as JSON; exit code `0` inside the policy, `1` warning, `3` outside it. Darkmoon does not
  change your pipelines: call it before your own scan step if you want the pipeline to respect the windows.
