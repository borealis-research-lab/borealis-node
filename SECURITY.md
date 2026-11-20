# Security policy

Borealis Node is experimental and not a production security product. No security support process or response time has been established yet.

## Reporting a vulnerability

If private vulnerability reporting is enabled for this repository, report suspected vulnerabilities through the **Security** tab using **Report a vulnerability**. Do not post real reports, logs or configuration files publicly.

## Security model, in brief

- `node.json` is trusted administrative configuration. It decides which programs run.
- Agent output is untrusted data. It is strictly parsed, fully validated, never executed or interpreted, and sanitised before display.
- On Windows, agents run in a Job Object assigned before the process runs (fail closed). On POSIX, agents run in their own process group, but a child that deliberately leaves the group can survive.
- The Node performs no detection and no remediation, and opens no network connections.
