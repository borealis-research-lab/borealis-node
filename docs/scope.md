# Borealis Node scope

- **Responsibility:** run the configured local agents and present their validated reports together.
- **Input:** `node.json` (trusted administrative configuration) and each agent's `borealis-agent-report/1` output.
- **Output:** one `borealis-node-report/1` report. Text output is optional.
- **Execution:** local. Agents run one after another, isolated and bounded.

## Non-goals

- Detection, correlation between agents, or changing or interpreting findings.
- Remediation or any change to the system.
- Networking, Borealis Core, remote coordination, scheduling, databases or AI.
- Installing, updating or discovering agents automatically. The administrator lists them.
