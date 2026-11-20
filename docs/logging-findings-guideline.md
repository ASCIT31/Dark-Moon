# Guideline: findings about missing or weak logging

This is reviewer and report-writer guidance for findings in the « security logging and monitoring » family (OWASP
A09, ISO 27001 A.8.15 / A.8.16, NIS2 art. 21(2)). It documents how such findings must be supported; it does **not**
change any agent prompt or agent behaviour.

## Rule: no claim without proof

A black-box test sees the application from outside. It almost never sees the target's logs, its SIEM or its alerting.
« The application does not log failed logins » is therefore not something a black-box test can observe on its own.

A logging finding is acceptable only with evidence that shows the gap, for example:

- a log file, log endpoint or monitoring console the test could read, showing that an event that happened during the
  test (a failed login, an injected payload, an access to an admin route) is absent from it;
- an exposed log or debug output showing the logged content is unsafe (secrets, session tokens or passwords written
  in clear; user input written unescaped so that a new line forges an entry);
- a documented and reproduced log-injection: the request, the resulting log line, and the forged entry;
- the customer's own statement, recorded as declared by the customer (not as a Darkmoon observation).

Without such evidence the finding is not reported as a weakness. At most it becomes a recommendation or a question for
the owner (« confirm that failed logins and admin actions are logged and alerted »), marked as not tested.

## How to word it

- Say what was observed and where; quote the log line or the response (secrets masked).
- Never extrapolate from one missing event to « no logging »; never infer « no SIEM » or « no alerting ».
- Severity follows the observed impact (for example a password written in clear in a readable log is a disclosure
  finding), not the absence of a control the test could not see.
- Framework mapping stays « technical evidence for » a control, never « non-compliant ».

## What Darkmoon itself logs

Darkmoon's own security events (sign-ins, administrator changes, campaign launches and maintenance blocks) are
described in the security events page; they are about the Darkmoon platform, not about the tested application.
