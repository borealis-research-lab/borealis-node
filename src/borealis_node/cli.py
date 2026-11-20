"""Command-line interface.

    borealis-node agents --config node.json
    borealis-node run    --config node.json [--json] [--out REPORT.json] [--include-diagnostics]

Exit codes for `run`: 0 = every agent ok; 1 = degraded or failed (a report is still
produced); 2 = configuration or output error.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from borealis_node import __version__, config, node, procexec
from borealis_node.validate import InvalidJson, strict_loads, validate_describe


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="borealis-node",
                                     description="Run configured Borealis agents locally and combine their reports.")
    parser.add_argument("--version", action="version", version=f"borealis-node {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    agents = sub.add_parser("agents", help="check each configured agent's identity and compatibility")
    agents.add_argument("--config", required=True)
    run = sub.add_parser("run", help="run every configured agent and print the combined report")
    run.add_argument("--config", required=True)
    run.add_argument("--json", action="store_true", help="print the borealis-node-report/1 JSON instead of text")
    run.add_argument("--out", metavar="REPORT.json", help="also save the JSON report (never overwrites); "
                                                          "omitted agent reports go to REPORT.json.agents/")
    run.add_argument("--include-diagnostics", action="store_true",
                     help="include sanitised, best-effort redacted agent stderr in the report (review before sharing)")
    return parser


def _err(message: str, code: int = 2) -> int:
    print(f"borealis-node: {message}", file=sys.stderr)
    return code


def cmd_agents(agents: list[config.AgentConfig]) -> int:
    worst = 0
    for agent in agents:
        exe = Path(agent.executable)
        if not exe.is_file():
            status = "missing"
        else:
            result = procexec.run(agent.executable, ["describe"], node.DESCRIBE_TIMEOUT, agent.cwd)
            try:
                problems = validate_describe(strict_loads(result.stdout), agent.expected_name) \
                    if result.exit_code == 0 and not result.launch_error else ["describe failed"]
            except InvalidJson:
                problems = ["describe output is not valid JSON"]
            status = "compatible" if not problems else "incompatible"
        worst = max(worst, 0 if status == "compatible" else 1)
        print(f"{node._safe(agent.config_name):<20} {status}")
    return worst


def cmd_run(args, agents: list[config.AgentConfig]) -> int:
    out_path = Path(args.out) if args.out else None
    sidecar_dir = None
    if out_path is not None:
        if out_path.exists():
            return _err(f"{out_path} already exists; refusing to overwrite it")
        sidecar_dir = out_path.with_name(out_path.name + ".agents")
        if sidecar_dir.exists():
            return _err(f"{sidecar_dir} already exists; refusing to overwrite it")
    started = time.time()
    entries, snippets = [], {}
    for agent in agents:
        entry, snippet = node.run_agent(agent, args.include_diagnostics)
        entries.append(entry)
        snippets[agent.config_name] = snippet
    if sidecar_dir is not None:
        sidecar_dir.mkdir(parents=True)  # created before use; fails if it appeared meanwhile
    report = node.build(entries, started, time.time(), sidecar_dir)
    if sidecar_dir is not None and not any(sidecar_dir.iterdir()):
        sidecar_dir.rmdir()
    text = node.serialise(report)
    if out_path is not None:
        try:
            with out_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            return _err(f"cannot write report to {out_path}: {exc.strerror or exc}")
        print(f"borealis-node: report saved to {out_path}", file=sys.stderr)
    sys.stdout.write(text if args.json else node.to_text(report, snippets))
    return 0 if report["outcome"] == "ok" else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        agents = config.load(args.config)
    except config.ConfigError as exc:
        return _err(str(exc))
    if args.command == "agents":
        return cmd_agents(agents)
    return cmd_run(args, agents)


if __name__ == "__main__":
    sys.exit(main())
