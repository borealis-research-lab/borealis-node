# Contributing to Borealis Node

Borealis Node has one responsibility: run the configured local agents and present their validated reports. It must never become a detector: no detection logic, no changes to findings, no remediation. Please discuss substantial changes in an issue first.

## Development

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pip install --no-build-isolation -e tests/fakeagent
python -m pytest
```

## Guidelines

- Behaviour changes need tests, especially for isolation, limits and validation.
- Never weaken a fail-closed path. Never add shell execution or PATH lookup.
- Output must conform to `borealis-node-report/1`. Never edit `tests/standards/`; re-copy it instead.
- Use synthetic data only. Never submit real reports, logs or configs.
