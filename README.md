# Borealis Node

Borealis Node runs the Borealis agents installed on this computer, checks their reports, and shows them together in one report. **It is an orchestrator, not a detector.** It never inspects security data itself, never changes an agent's findings, and never acts on anything an agent reports.

Part of [Borealis Research](https://github.com/borealis-research-lab). It reads agent reports in the [`borealis-agent-report/1`](https://github.com/borealis-research-lab/.github/tree/main/standards) format and writes `borealis-node-report/1`.

> **Experimental.** Not a production security product.

## ⚠ Trust model: `node.json` is trusted administrative configuration

**Anyone who can edit `node.json` can make Borealis Node run any program on this computer.** Protect it like any administrator-owned configuration file.

The Node runs only what that file lists:
- an **absolute path** to an existing executable (no PATH lookup);
- an argument list (**no shell**).

stdin is closed. The Node itself opens no network connections. It can't stop an agent from using the network; trusting an agent is your decision, made by listing it.

## What it does

For each configured agent, one at a time:
1. Runs `<agent> describe` and checks that the agent's identity matches `expected_name` and that it speaks `borealis-agent-report/1`.
2. Runs the agent with its configured arguments, under isolation and limits (below).
3. Parses its output strictly (UTF-8; no duplicate keys, NaN or floats) and checks the full standard, including every invariant. The report's `agent.name` must also match.
4. Adds the agent's report **unchanged** to the combined report, attributed by its entry.

**Outcomes:**
- **Agent:**
  - a valid `ok` report gives `ok`;
  - a valid `partial` report gives `degraded`;
  - a valid `error` report, or any failure (launch, timeout, crash, invalid report) gives `failed`.
- **Node:**
  - `ok` if every agent is `ok`;
  - `failed` if no agent produced usable analysis;
  - otherwise `degraded`.

**Failures are always visible.** Every agent gets an entry saying what happened.

## Usage

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"    # Windows paths shown

borealis-node agents --config node.json          # check each agent's identity and compatibility
borealis-node run    --config node.json          # human-readable summary
borealis-node run    --config node.json --json   # borealis-node-report/1
borealis-node run    --config node.json --json --out report.json
```

Exit codes for `run`: **0** = every agent ok; **1** = degraded or failed (a report is still produced); **2** = a configuration or output error.

`node.json` (at most 32 agents):

```json
{"agents": [
  {"config_name": "nyyrikki", "expected_name": "nyyrikki",
   "executable": "C:/borealis/security-event-analysis/.venv/Scripts/nyyrikki.exe",
   "args": ["scan", "C:/borealis/exports/security.xml"], "timeout_s": 300},
  {"config_name": "ilmarinen", "expected_name": "ilmarinen",
   "executable": "C:/borealis/file-integrity/.venv/Scripts/ilmarinen.exe",
   "args": ["check", "--config", "C:/borealis/ilmarinen.json", "--expected-digest", "<digest>"], "timeout_s": 600}
]}
```

`config_name` matches `[a-z][a-z0-9-]{0,31}` and must be unique; it's also used as a file name. `timeout_s` is 1–86400. `cwd` is optional and must be an absolute path to an existing directory.

## Isolation and limits

| | Windows | Linux / POSIX |
|---|---|---|
| **Start** | `CreateProcessW` **suspended**, assigned to a Job Object (`KILL_ON_JOB_CLOSE`, no breakaway), then resumed via the returned primary thread handle. **If the job can't be set up, the process is terminated before it runs any code** (`isolation-failed`) | New session and process group |
| **Inherited handles** | Only stdin (NUL), stdout and stderr | stdin closed; other descriptors closed |
| **On timeout or too much output** | Closing the job kills the agent **and all its descendants** | The whole process group is killed. **Limitation:** a child that deliberately leaves the group can survive |
| **Output limits** | stdout 10 MiB, stderr 64 KiB, both read on background threads | same |

### Not a security sandbox

This isolation is **process-tree containment and resource bounding, not a security sandbox**:
- **Windows Job Objects** contain the process tree, but don't restrict filesystem or network access.
- **Linux process groups** are process management, not a security boundary against a deliberately hostile agent.
- Neither platform currently enforces a **CPU or memory quota**.

Borealis Node is meant for agents an administrator has deliberately installed and trusts. **Don't use it to run untrusted third-party agents.**

## Report size and output files

- The combined report never exceeds **64 MiB**:
  - 8 MiB is reserved for the Node's own fields, all of which are bounded;
  - each agent's embedded report gets `56 MiB / number of agents`.
- A larger report is not embedded: the entry shows `omitted-for-size`, a summary, and `complete: false`. With `--out report.json`, the full report is saved as `report.json.agents/<config_name>.json`, and the summary records only that file name.
- `--out` **never overwrites** an existing report or sidecar directory.

## Privacy

- **Agent stderr isn't in the report by default.** For a failed agent, a sanitised snippet is shown on your terminal only.
- `--include-diagnostics` puts a snippet in the report: at most 2000 characters, with escape sequences and control characters removed, and your home path and user name replaced. **The redaction is best effort: review such reports before sharing them.**
- Agent reports can contain personal data (see each agent's `describe`), and so can the combined report. Keep it local unless you've reviewed it.
- All text from agents is treated as data. Escape sequences and control characters are stripped before anything is shown on the terminal.

## Tests

`python -m pytest`. The tests use a fake agent (`tests/fakeagent`, installed with `pip install --no-build-isolation -e tests/fakeagent`) and synthetic data only. `tests/standards/` holds unmodified copies of the standard's schemas, vectors and reference checker.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
