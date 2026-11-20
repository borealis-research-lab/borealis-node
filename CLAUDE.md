# Borealis Node: instructions for Claude Code

Borealis Node runs configured local Borealis agents and presents their validated reports (`borealis-node-report/1`). See [Borealis Architecture v1](https://github.com/borealis-research-lab/.github/blob/main/architecture/borealis-architecture-v1.md).

- **The Node is an orchestrator, not a detector.** Never add detection logic, never modify, add or drop findings, never remediate.
- `node.json` is trusted administrative configuration. Absolute executables only, no shell, no PATH lookup.
- **Agent output is untrusted:** strict JSON, full `borealis-agent-report/1` validation including the invariants, identity checks, and sanitising before display.
- **Fail closed:** on Windows, agents start suspended in a Job Object; never fall back to unisolated execution.
- Nothing is silently dropped. Keep every bounded field bounded, and keep the 64 MiB guarantee.
- No networking, AI, databases or Core functionality here. Standard library only at runtime.
- `tests/standards/` holds vendored, unmodified copies; never edit them. Tests use synthetic data only.

Run tests with `python -m pytest` (install `tests/fakeagent` first).
