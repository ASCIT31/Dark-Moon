# Security events and log format

Darkmoon writes security events with stable names on the `darkmoon.audit` logger (Community: the MCP server's stderr). The catalogue lives in the shared
core (`mcp/api/exec_core/taxonomy.py`); the log adapter (`mcp/api/security_log.py`) is the same file in both
editions.

## Log format

| `DARKMOON_LOG_FORMAT` | Output (stderr) |
|---|---|
| unset / `text` (default) | unchanged for every existing logger; security events as `<time> <LEVEL> darkmoon.audit security-event event=… outcome=… severity=…` |
| `json` | every `darkmoon.*` record as one JSON object per line; security events with the fields below, other records as `{"at", "level", "logger", "message"}` |

When the deployment already configured a handler on these loggers, Darkmoon adds none. Events of severity `medium` or
`high` are written at WARNING level, the others at INFO.

## Fields

`schema` (`darkmoon-security-event/1`), `event`, `category`, `action`, `outcome` (`success`, `failure`,
`blocked`, `override`, `warning`), `severity` (`info`, `low`, `medium`, `high`, fixed per event and outcome),
`at` (UTC), `actor`, `actor_role`, `via` (`bearer`, `session`, `service`, `scheduler`, `mcp`, `cli`),
`source_ip` (the socket peer; a forwarded header is not trusted), `target` (ids), `reason`, `details`.

The names were chosen to map easily onto common SIEM schemas (category / action / outcome / user / source address).
**No conformance to OCSF, ECS or any other schema is claimed or validated.**

## Hygiene

- No secret: a key that names a secret (password, token, secret, cookie, CSRF, authorization, API key, credential,
  session, private key…) keeps its key and loses its value (`[redacted]`); a value shaped like a bearer token, a JWT
  or a provider key is replaced too. Passwords, tokens, CSRF values, webhook URLs and secrets are never passed to an
  event in the first place.
- No log injection: new lines, ANSI escapes, C1 and bidi characters in any value (a user name typed at the login
  form included) are written as visible escapes; one event is always one line.
- Bounded: text values are cut, at most 20 detail keys.
- Failed sign-ins say « invalid credentials » whether the account exists or not.

## Catalogue

| Event | Category | Action | Outcome → severity | Meaning |
|---|---|---|---|---|
| `admin.application_profile.replace` | configuration | application_profile_replace | success → low, failure → medium | The declared application profile of a project was replaced. |
| `admin.credential.create` | configuration | credential_create | success → low, failure → medium | A stored credential was added. |
| `admin.credential.delete` | configuration | credential_delete | success → low, failure → medium | A stored credential was deleted. |
| `admin.credential.update` | configuration | credential_update | success → low, failure → medium | A stored credential was changed. |
| `admin.ebios_context.replace` | configuration | ebios_context_replace | success → low, failure → medium | The EBIOS RM context of a project was replaced. |
| `admin.evidence_token.revoke` | iam | evidence_token_revoke | success → low, failure → medium | A run evidence token was revoked. |
| `admin.finding.quarantine_review` | configuration | finding_quarantine_review | success → low, failure → medium | A quarantined finding was reviewed. |
| `admin.maintenance_policy.replace` | configuration | maintenance_policy_replace | success → low, failure → medium | The maintenance policy of a project was replaced. |
| `admin.operator_path.change` | configuration | operator_path_change | success → low, failure → medium | An operator-declared attack path was created, changed, deleted or restored. |
| `admin.schedule.create` | configuration | schedule_create | success → low, failure → medium | A scheduled campaign was created. |
| `admin.schedule.delete` | configuration | schedule_delete | success → low, failure → medium | A scheduled campaign was deleted. |
| `admin.schedule.update` | configuration | schedule_update | success → low, failure → medium | A scheduled campaign was changed. |
| `admin.treatment_action.update` | configuration | treatment_action_update | success → low, failure → medium | A treatment action's status or declarations were changed. |
| `admin.webhook.create` | configuration | webhook_create | success → low, failure → medium | A webhook was registered. |
| `admin.webhook.delete` | configuration | webhook_delete | success → low, failure → medium | A webhook was deleted. |
| `auth.csrf_rejected` | authentication | csrf_check | failure → medium | A state-changing request on a cookie session came without a valid CSRF token. |
| `auth.login` | authentication | login | success → info, failure → medium | An account signed in, or a sign-in was refused. |
| `auth.logout` | authentication | logout | success → info | An account signed out (every session of the account is revoked). |
| `auth.password_change` | authentication | password_change | success → low, failure → medium | An account changed its password, or the current password was wrong. |
| `auth.service_token_issue` | iam | service_token_issue | success → medium | A service token was issued (command line). |
| `authz.admin_denied` | iam | authorization_check | failure → medium | A non-administrator tried an administrator-only change. |
| `campaign.launch` | campaign | launch | success → info, warning → low, blocked → medium, override → high, failure → medium | A campaign launch: started, started with a maintenance warning, blocked by the maintenance policy, started by an administrator override, or refused (scope). |
| `campaign.stop` | campaign | stop | success → low, failure → medium | A running campaign was stopped. |

Community has no accounts or admin routes: its MCP server emits `campaign.launch` (`success` / `warning`, from the
maintenance check at campaign start). The other events of the catalogue are emitted by Darkmoon Pro. Names are never
renamed once shipped; a new meaning gets a new name. There is no account lockout in the product today, so no lockout event.
