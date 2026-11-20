"""Runs configured agents and assembles a borealis-node-report/1 report.

Borealis Node is an orchestrator, not a detector: it never inspects security data itself,
never changes agent findings, and attributes every report to its agent through the
enclosing entry. Failures are always visible.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from borealis_node import __version__, procexec
from borealis_node.config import AgentConfig
from borealis_node.validate import InvalidJson, strict_loads, validate_agent_report, validate_describe

NODE_STANDARD = "borealis-node-report/1"
MAX_NODE_BYTES = 64 * 1024 * 1024
ENVELOPE_RESERVE = 8 * 1024 * 1024
EMBED_BUDGET = MAX_NODE_BYTES - ENVELOPE_RESERVE
DESCRIBE_TIMEOUT = 30.0
MAX_PROBLEMS = 50
MAX_SUMMARY_IDS = 200
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b.")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def ts(epoch: float) -> str:
    t = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (f".{t.microsecond:06d}" if t.microsecond else "") + "Z"


def sanitise(text: str, limit: int = 2000) -> str:
    """For any agent-supplied text shown or stored by the Node: no escape sequences or controls."""
    return _CONTROL.sub(" ", _ANSI.sub("", text))[:limit]


def redact(text: str) -> str:
    home = os.path.expanduser("~")
    for value, label in ((home, "<home>"), (home.replace("\\", "/"), "<home>")):
        if value and len(value) > 3:
            text = re.sub(re.escape(value), label, text, flags=re.IGNORECASE)
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name available: nothing to redact
        user = ""
    if len(user) >= 3:
        text = re.sub(re.escape(user), "<user>", text, flags=re.IGNORECASE)
    return text


def _cj_size(report: Any) -> int:
    return len(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _problems(items: list[str]) -> dict:
    return {"problems": items[:MAX_PROBLEMS], "problems_total": len(items)}


def run_agent(agent: AgentConfig, include_diagnostics: bool) -> tuple[dict, str]:
    """Returns (agent entry without embedding decisions, sanitised stderr snippet for the terminal)."""
    entry: dict[str, Any] = {
        "config_name": agent.config_name, "expected_name": agent.expected_name, "outcome": "failed",
        "execution": {"started_at": "", "finished_at": "", "exit_code": None, "timed_out": False, "killed": False,
                      "stdout_bytes": 0, "output_too_large": False, "launch_error": None},
        "validation": {"result": "not-run", **_problems([])}, "diagnostic": None,
        "report_embedding": "none", "report": None, "report_summary": None,
    }
    if not os.path.exists(agent.executable):
        now = ts(datetime.now(timezone.utc).timestamp())
        entry["execution"].update(started_at=now, finished_at=now, launch_error="not-found")
        return entry, ""
    if not os.path.isfile(agent.executable):
        now = ts(datetime.now(timezone.utc).timestamp())
        entry["execution"].update(started_at=now, finished_at=now, launch_error="not-a-file")
        return entry, ""

    # 1. Identity: describe must match the configured identity.
    described = procexec.run(agent.executable, ["describe"], DESCRIBE_TIMEOUT, agent.cwd)
    describe_problems: list[str] = []
    if described.launch_error:
        entry["execution"].update(started_at=ts(described.started), finished_at=ts(described.finished),
                                  launch_error=described.launch_error)
        return entry, ""
    try:
        describe_problems = validate_describe(strict_loads(described.stdout), agent.expected_name) \
            if not (described.timed_out or described.output_too_large or described.exit_code != 0) \
            else ["describe: did not complete successfully"]
    except InvalidJson:
        describe_problems = ["describe: output is not valid JSON"]
    if describe_problems:
        mismatch = any("does not match expected_name" in d for d in describe_problems)
        entry["execution"].update(started_at=ts(described.started), finished_at=ts(described.finished),
                                  launch_error="describe-mismatch" if mismatch else "describe-failed",
                                  timed_out=described.timed_out, killed=described.killed)
        entry["validation"] = {"result": "invalid", **_problems(describe_problems)}
        return entry, sanitise(described.stderr.decode("utf-8", "replace"))

    # 2. The run itself.
    result = procexec.run(agent.executable, agent.args, agent.timeout_s, agent.cwd)
    entry["execution"] = {
        "started_at": ts(result.started), "finished_at": ts(result.finished), "exit_code": result.exit_code,
        "timed_out": result.timed_out, "killed": result.killed, "stdout_bytes": len(result.stdout),
        "output_too_large": result.output_too_large, "launch_error": result.launch_error,
    }
    snippet = sanitise(result.stderr.decode("utf-8", "replace"))
    if include_diagnostics and snippet:
        entry["diagnostic"] = redact(snippet)[:2000]
    if result.launch_error or result.timed_out or result.output_too_large or result.killed:
        return entry, snippet
    if result.exit_code != 0:
        entry["validation"] = {"result": "invalid", **_problems(["run: agent exited without a valid report"])}
        return entry, snippet

    # 3. Validation: strict JSON, the closed v1 schema and every invariant, plus identity.
    try:
        report = strict_loads(result.stdout)
        problems = validate_agent_report(report, len(result.stdout))
    except InvalidJson as exc:
        report, problems = None, [f"report: {exc}"]
    if report is not None and not problems:
        agent_field = report.get("agent") if isinstance(report, dict) else None
        if not isinstance(agent_field, dict) or agent_field.get("name") != agent.expected_name:
            problems = ["report: agent.name does not match expected_name"]
    if problems:
        entry["validation"] = {"result": "invalid", **_problems(problems)}
        return entry, snippet
    entry["validation"] = {"result": "valid", **_problems([])}
    entry["report"] = report
    entry["report_embedding"] = "embedded"
    entry["outcome"] = {"ok": "ok", "partial": "degraded"}.get(report["status"], "failed")
    return entry, snippet


def _summary(report: dict, saved_as: str | None) -> dict:
    findings = report["findings"]
    return {
        "bytes": _cj_size(report), "status": report["status"], "findings_total": report["findings_total"],
        "counts_by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in ("low", "medium", "high")},
        "finding_ids": [f["finding_id"] for f in findings[:MAX_SUMMARY_IDS]],
        "finding_ids_total": len(findings), "saved_as": saved_as,
    }


def _omit(entry: dict, sidecar_dir: Path | None) -> None:
    report = entry["report"]
    saved_as = None
    if sidecar_dir is not None:
        name = f"{entry['config_name']}.json"
        with open(sidecar_dir / name, "x", encoding="utf-8", newline="\n") as handle:  # never overwrites
            handle.write(json.dumps(report, indent=2) + "\n")
        saved_as = name
    entry.update(report=None, report_embedding="omitted-for-size", report_summary=_summary(report, saved_as))


def serialise(report: dict) -> str:
    return json.dumps(report, indent=2) + "\n"


def build(entries: list[dict], started: float, finished: float, sidecar_dir: Path | None) -> dict:
    budget = EMBED_BUDGET // max(len(entries), 1)
    for entry in entries:
        if entry["report"] is not None and _cj_size(entry["report"]) > budget:
            _omit(entry, sidecar_dir)
    outcomes = [e["outcome"] for e in entries]
    usable = [o for o in outcomes if o in ("ok", "degraded")]
    outcome = "ok" if all(o == "ok" for o in outcomes) else ("failed" if not usable else "degraded")
    report = {
        "standard": NODE_STANDARD,
        "node": {"name": "borealis-node", "version": __version__},
        "run": {"id": str(uuid.uuid4()), "started_at": ts(started), "finished_at": ts(finished)},
        "outcome": outcome, "complete": True, "agents": entries,
    }
    # Final guarantee: never exceed 64 MiB; omit embedded reports in reverse config order.
    for entry in reversed(entries):
        if len(serialise(report).encode("utf-8")) <= MAX_NODE_BYTES:
            break
        if entry["report"] is not None:
            _omit(entry, sidecar_dir)
    report["complete"] = not any(e["report_embedding"] == "omitted-for-size" for e in entries)
    return report


# --- human-readable view -----------------------------------------------------------------------


def _safe(value: Any) -> str:
    out = []
    for ch in str(value):
        code = ord(ch)
        if ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def findings_summary(report: dict) -> list[str]:
    """Separates WHAT WAS FOUND from WHETHER THE ANALYSIS RAN. Counts come only from the
    agents' own reports (embedded or summarised); the Node does not assess findings itself."""
    total, by_severity, unknown = 0, {"high": 0, "medium": 0, "low": 0}, []
    for e in report["agents"]:
        if e["report"] is not None:
            total += e["report"]["findings_total"]
            for f in e["report"]["findings"]:
                by_severity[f["severity"]] += 1
        elif e["report_summary"] is not None:
            total += e["report_summary"]["findings_total"]
            for severity, n in e["report_summary"]["counts_by_severity"].items():
                by_severity[severity] += n
        else:
            unknown.append(_safe(e["config_name"]))
    listed = sum(by_severity.values())
    lines = [f"Findings: {total} ({by_severity['high']} high, {by_severity['medium']} medium, {by_severity['low']} low)"]
    if total > listed:
        lines.append(f"  plus {total - listed} not listed by the reporting agent(s) because of report limits")
    if unknown:
        lines.append(f"  unknown for: {', '.join(unknown)} (no valid report)")
    if report["outcome"] == "ok" and total:
        lines.append("Note: outcome 'ok' means every agent completed its analysis. It does not mean nothing was found.")
    elif report["outcome"] == "ok":
        lines.append("Note: no findings does not mean the system is safe; agents only check what they are configured to check.")
    else:
        lines.append("Note: the outcome describes whether the agents' analysis completed; the findings describe what they found.")
    return lines


def to_text(report: dict, snippets: dict[str, str]) -> str:
    lines = ["Borealis Node Report", "====================", "",
             f"Outcome: {report['outcome']}" + ("" if report["complete"] else " (some reports omitted for size)"),
             *findings_summary(report), "",
             f"{'Agent':<20} {'Outcome':<10} {'Findings':>8}  Notes"]
    for e in report["agents"]:
        source = e["report"] or e["report_summary"]
        findings = source["findings_total"] if source else "-"
        notes = []
        ex = e["execution"]
        if ex["launch_error"]:
            notes.append(ex["launch_error"])
        if ex["timed_out"]:
            notes.append("timed out")
        if ex["output_too_large"]:
            notes.append("output too large")
        if e["validation"]["result"] == "invalid":
            notes.append(f"invalid report ({e['validation']['problems_total']} problems)")
        if source and source.get("status") in ("partial", "error"):
            notes.append(f"agent status {source['status']}")
        if e["report_embedding"] == "omitted-for-size":
            notes.append("omitted for size" + (f", saved as {e['report_summary']['saved_as']}" if e["report_summary"]["saved_as"] else ""))
        lines.append(f"{_safe(e['config_name']):<20} {e['outcome']:<10} {findings!s:>8}  {'; '.join(notes)}")
    for e in report["agents"]:
        if e["outcome"] == "failed" and snippets.get(e["config_name"]):
            lines += ["", f"[{_safe(e['config_name'])}] agent error output (local only, sanitised):",
                      "  " + _safe(snippets[e["config_name"]][:500])]
    for e in report["agents"]:
        r = e["report"]
        if not r or not r["findings"]:
            continue
        lines += ["", f"Findings from {_safe(e['config_name'])} ({_safe(r['agent']['name'])} {_safe(r['agent']['version'])})",
                  "-" * 40]
        for f in sorted(r["findings"], key=lambda f: {"high": 0, "medium": 1, "low": 2}[f["severity"]]):
            lines.append(f"  [{f['severity'].upper()}] {_safe(f['rule_id'])}: {_safe(f['observation'])}")
    lines += ["", "Severity is each agent's rule label, not a probability. Borealis Node does not perform detection."]
    return "\n".join(lines) + "\n"
