"""Borealis synthetic integration test.

Runs the REAL installed agents (Nyyrikki, Ilmarinen) and Borealis Node together through
five stages, using only synthetic data generated in a fresh temporary directory:

  1. Agent discovery and identity validation
  2. Ilmarinen baseline lifecycle, change detection, refusal of incomplete baselines
  3. Nyyrikki detection on synthetic Windows Security XML, deterministic finding IDs
  4. Node orchestration: validation, attribution, unchanged embedding, combined findings
  5. Failure handling: missing agent, corrupted baseline, rewritten baseline, expected digest

plus a privacy check of every saved evidence file.

Usage (absolute paths to the installed executables; no PATH lookup):

  python integration/run_integration.py \
      --nyyrikki /abs/path/nyyrikki --ilmarinen /abs/path/ilmarinen \
      --borealis-node /abs/path/borealis-node --out ./integration-evidence

Exit code 0 = every check passed; 1 = at least one check failed; 2 = setup error.
Standard library only. Reports are validated with the vendored reference checker in
tests/standards/ (an unmodified copy of the Borealis standards' checker).
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests" / "standards"))
import check_report as std  # noqa: E402  (vendored reference checker)

WINDOWS = os.name == "nt"
ATTACK_FILE = "attack-export-PRIVATE-NAME.xml"  # a distinctive name: it must never appear in reports
BENIGN_FILE = "benign-export-PRIVATE-NAME.xml"
EXPECTED_RULES = {
    "failed-logon-burst": set(range(2001, 2013)),
    "failed-then-success": set(range(2001, 2014)),
    "account-created": {2014},
    "privileged-group-add": {2015},
    "audit-log-cleared": {2016},
}


# --- result bookkeeping ----------------------------------------------------------------------------


class Stage:
    def __init__(self, name: str) -> None:
        self.name = name
        self.checks: list[tuple[str, bool, str]] = []
        self.notes: list[str] = []

    def check(self, description: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((description, bool(ok), detail))
        return bool(ok)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(ok for _, ok, _ in self.checks)


class Run:
    def __init__(self, args, workspace: Path, evidence: Path) -> None:
        self.args, self.ws, self.evidence = args, workspace, evidence
        self.stages: list[Stage] = []

    def stage(self, name: str) -> Stage:
        stage = Stage(name)
        self.stages.append(stage)
        return stage

    def exec(self, *cmd, timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run([str(c) for c in cmd], capture_output=True, timeout=timeout)

    def save(self, name: str, data: bytes | str) -> None:
        (self.evidence / name).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def text(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout + proc.stderr).decode("utf-8", "replace")


def load_agent(data: bytes, stage: Stage, label: str) -> dict | None:
    try:
        report = std.strict_loads(data)
    except std.StrictJsonError as exc:
        stage.check(f"{label}: output is strict JSON", False, str(exc))
        return None
    problems = std.validate_agent_report(report, len(data))
    stage.check(f"{label}: valid borealis-agent-report/1", not problems, "; ".join(problems[:3]))
    return report


def load_node(data: bytes, stage: Stage, label: str) -> dict | None:
    try:
        report = std.strict_loads(data)
    except std.StrictJsonError as exc:
        stage.check(f"{label}: output is strict JSON", False, str(exc))
        return None
    problems = std.validate_node_report(report, len(data))
    stage.check(f"{label}: valid borealis-node-report/1", not problems, "; ".join(problems[:3]))
    return report


def stable(report: dict) -> dict:
    """A report without per-run fields (run id/times and finding created_at)."""
    out = {k: v for k, v in report.items() if k != "run"}
    out["findings"] = [{k: v for k, v in f.items() if k != "created_at"} for f in report["findings"]]
    return out


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- synthetic data ------------------------------------------------------------------------------


def _event(record: int, event_id: int, minute: int, second: int, data: dict | None = None,
           provider: str = "Microsoft-Windows-Security-Auditing", user_data: dict | None = None) -> str:
    from xml.sax.saxutils import escape, quoteattr

    body = ""
    if data:
        body = "<EventData>" + "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items()) + "</EventData>"
    if user_data:
        body += ('<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
                 + "".join(f"<{k}>{escape(v)}</{k}>" for k, v in user_data.items()) + "</LogFileCleared></UserData>")
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="2026-11-20T09:{minute:02d}:{second:02d}.0000000Z"/>'
            f"<EventRecordID>{record}</EventRecordID><Channel>Security</Channel>"
            f"<Computer>WS01.example.test</Computer></System>{body}</Event>")


def _logon(record, event_id, minute, second, user, ip="203.0.113.50"):
    data = {"TargetUserName": user, "TargetDomainName": "WS01", "LogonType": "3", "IpAddress": ip}
    if event_id == 4625:
        data.update(Status="0xc000006d", SubStatus="0xc000006a")
    return _event(record, event_id, minute, second, data)


def synthetic_attack() -> str:
    events = [_logon(2000, 4624, 0, 0, "alice", "192.0.2.10")]
    events += [_logon(2001 + i, 4625, 10, i * 4, "administrator") for i in range(12)]
    events.append(_logon(2013, 4624, 11, 0, "administrator"))
    events.append(_event(2014, 4720, 12, 0, {"TargetUserName": "svc-update", "TargetDomainName": "WS01",
                                            "TargetSid": "S-1-5-21-1-2-3-1010", "SubjectUserName": "admin"}))
    events.append(_event(2015, 4732, 12, 10, {"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1010",
                                             "TargetUserName": "Administrators", "TargetDomainName": "Builtin",
                                             "TargetSid": "S-1-5-32-544", "SubjectUserName": "admin"}))
    events.append(_event(2016, 1102, 13, 20, provider="Microsoft-Windows-Eventlog",
                         user_data={"SubjectUserName": "admin", "SubjectDomainName": "WS01"}))
    return "<!-- SYNTHETIC test data generated by run_integration.py -->\n" + "\n".join(events) + "\n"


def synthetic_benign() -> str:
    events = [_logon(1000 + i, 4624, i, 0, u, "192.0.2.10") for i, u in enumerate(["alice", "bob", "carol"])]
    events += [_logon(1010, 4625, 20, 0, "bob", "192.0.2.11"), _logon(1011, 4624, 20, 10, "bob", "192.0.2.11")]
    events.append(_event(1012, 4732, 30, 0, {"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1011",
                                             "TargetUserName": "Users", "TargetSid": "S-1-5-32-545",
                                             "SubjectUserName": "admin"}))
    return "<!-- SYNTHETIC test data generated by run_integration.py -->\n" + "\n".join(events) + "\n"


# --- stages --------------------------------------------------------------------------------------


def setup(run: Run) -> dict:
    ws = run.ws
    (ws / "monitored" / "config").mkdir(parents=True)
    (ws / "monitored" / "config" / "app.conf").write_text("synthetic setting=1\n")
    (ws / "monitored" / "README.txt").write_text("synthetic readme\n")
    (ws / "state").mkdir()
    (ws / ATTACK_FILE).write_text(synthetic_attack())
    (ws / BENIGN_FILE).write_text(synthetic_benign())
    ilm_cfg = ws / "ilmarinen.json"
    ilm_cfg.write_text(json.dumps({"roots": [{"id": "testapp", "path": str(ws / "monitored"), "recursive": True,
                                              "exclude": []}], "baseline": str(ws / "state" / "baseline.json")}))
    nyy = {"config_name": "nyyrikki", "expected_name": "nyyrikki", "executable": run.args.nyyrikki,
           "args": ["scan", str(ws / ATTACK_FILE)], "timeout_s": 120}
    ilm = {"config_name": "ilmarinen", "expected_name": "ilmarinen", "executable": run.args.ilmarinen,
           "args": ["check", "--config", str(ilm_cfg)], "timeout_s": 120}
    return {"ilm_cfg": ilm_cfg, "nyy": nyy, "ilm": ilm, "baseline": ws / "state" / "baseline.json"}


def write_node_config(run: Run, name: str, agents: list[dict]) -> Path:
    path = run.ws / f"node-{name}.json"
    path.write_text(json.dumps({"agents": agents}))
    return path


def stage1(run: Run, ctx: dict) -> None:
    s = run.stage("1. Agent discovery and identity validation")
    cfg = write_node_config(run, "main", [ctx["nyy"], ctx["ilm"]])
    proc = run.exec(run.args.borealis_node, "agents", "--config", cfg)
    run.save("1-agents.txt", proc.stdout)
    lines = [line.split() for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    s.check("borealis-node agents exits 0", proc.returncode == 0, text(proc)[:200])
    found = {parts[0]: parts for parts in lines}
    for name in ("nyyrikki", "ilmarinen"):
        parts = found.get(name, [])
        s.check(f"{name}: compatible, with validated name and version shown",
                len(parts) == 4 and parts[1] == "compatible" and parts[2] == name, " ".join(parts))
        if len(parts) == 4:
            ctx[f"{name}_version"] = parts[3]


def stage2(run: Run, ctx: dict) -> None:
    s = run.stage("2. Ilmarinen baseline lifecycle and change detection")
    ilm, cfg, base, mon = run.args.ilmarinen, ctx["ilm_cfg"], ctx["baseline"], run.ws / "monitored"

    proc = run.exec(ilm, "baseline", "create", "--config", cfg)
    run.save("2.1-baseline-create.txt", proc.stdout)
    out = proc.stdout.decode("utf-8", "replace")
    digest = out.split("Baseline digest: ")[1].split()[0] if "Baseline digest: " in out else ""
    ctx["digest"] = digest
    s.check("create baseline: exit 0 and a digest is printed", proc.returncode == 0 and len(digest) == 64, text(proc)[:200])
    entries = sorted(e["ref"] for e in json.loads(base.read_text())["entries"]) if base.exists() else []
    s.check("baseline contains exactly config/app.conf and README.txt",
            entries == ["file:testapp:README.txt", "file:testapp:config/app.conf"], str(entries))
    ctx["baseline_sha"] = sha256_file(base) if base.exists() else ""

    proc = run.exec(ilm, "baseline", "create", "--config", cfg)
    run.save("2.2-baseline-create-again.txt", proc.stdout + proc.stderr)
    s.check("second create is refused (exit 1)", proc.returncode == 1, text(proc)[:200])
    s.check("baseline unchanged after the refused create", base.exists() and sha256_file(base) == ctx["baseline_sha"])

    def check(label: str, *extra) -> dict | None:
        p = run.exec(ilm, "check", "--config", cfg, *extra)
        run.save(f"{label}.json", p.stdout)
        s.check(f"{label}: exit 0", p.returncode == 0, text(p)[-200:])
        return load_agent(p.stdout, s, label)

    def rules(r):
        return sorted((f["rule_id"], f["evidence"][0]["ref"]) for f in r["findings"]) if r else None

    r = check("2.3-check-unchanged")
    s.check("unchanged: status ok, 0 findings", r and r["status"] == "ok" and r["findings_total"] == 0)
    r = check("2.4-check-with-expected-digest", "--expected-digest", digest)
    s.check("expected digest verified independently",
            r and r.get("extensions", {}).get("digest_verified_independently") is True)

    (mon / "config" / "app.conf").write_text("synthetic setting=2\n")
    r = check("2.5-check-modified")
    s.check("modify: exactly file-changed on config/app.conf",
            rules(r) == [("file-changed", "file:testapp:config/app.conf")], str(rules(r)))
    (mon / "config" / "extra.conf").write_text("synthetic new file\n")
    r = check("2.6-check-added")
    s.check("add: file-added on config/extra.conf (cumulative with the change)",
            rules(r) == [("file-added", "file:testapp:config/extra.conf"),
                         ("file-changed", "file:testapp:config/app.conf")], str(rules(r)))
    (mon / "README.txt").unlink()
    r = check("2.7-check-deleted")
    expected = [("file-added", "file:testapp:config/extra.conf"), ("file-changed", "file:testapp:config/app.conf"),
                ("file-deleted", "file:testapp:README.txt")]
    s.check("delete: file-deleted on README.txt (cumulative)", rules(r) == expected, str(rules(r)))
    ctx["ilmarinen_standalone"] = r

    # Incomplete scan: an entry that cannot be checked must block baseline creation.
    inc = run.ws / "incomplete"
    (inc / "data").mkdir(parents=True)
    (inc / "state").mkdir()
    (inc / "data" / "readable.txt").write_text("a\n")
    inc_cfg = inc / "ilmarinen.json"
    inc_cfg.write_text(json.dumps({"roots": [{"id": "inc", "path": str(inc / "data"), "recursive": True, "exclude": []}],
                                   "baseline": str(inc / "state" / "baseline.json")}))
    if WINDOWS:
        method, code = "an exclusively locked file (Windows)", "unreadable"
        (inc / "data" / "locked.txt").write_text("b\n")
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        handle = k32.CreateFileW(str(inc / "data" / "locked.txt"), 0x80000000, 0, None, 3, 0, None)
        try:
            proc = run.exec(ilm, "baseline", "create", "--config", inc_cfg)
        finally:
            k32.CloseHandle(handle)
    else:
        method, code = "a FIFO, which Ilmarinen never opens (POSIX; works even as root)", "unsupported-entry"
        os.mkfifo(inc / "data" / "pipe")
        proc = run.exec(ilm, "baseline", "create", "--config", inc_cfg, timeout=60)
    s.notes.append(f"incomplete-scan check used {method}")
    run.save("2.8-incomplete-baseline-create.txt", proc.stdout + proc.stderr)
    s.check(f"incomplete scan: baseline refused (exit 1, reports {code})",
            proc.returncode == 1 and code in text(proc) and "incomplete scan" in text(proc), text(proc)[:200])
    s.check("incomplete scan: no baseline and no temporary files written", not any((inc / "state").iterdir()))


def stage3(run: Run, ctx: dict) -> None:
    s = run.stage("3. Nyyrikki synthetic event detection")
    nyy = run.args.nyyrikki
    reports = []
    for i in (1, 2):
        p = run.exec(nyy, "scan", run.ws / ATTACK_FILE)
        run.save(f"3.{i}-nyyrikki-attack-run{i}.json", p.stdout)
        s.check(f"attack run {i}: exit 0", p.returncode == 0, text(p)[-200:])
        reports.append(load_agent(p.stdout, s, f"attack run {i}"))
    r1, r2 = reports
    if r1:
        rules = {}
        for f in r1["findings"]:
            rules.setdefault(f["rule_id"], []).append({int(e["ref"].rsplit(":", 1)[1]) for e in f["evidence"]})
        for rule, records in EXPECTED_RULES.items():
            s.check(f"{rule}: fires exactly once on records {min(records)}-{max(records)}",
                    rules.get(rule) == [records], str(rules.get(rule)))
        s.check("no other rules fire", set(rules) == set(EXPECTED_RULES), str(sorted(rules)))
        ctx["nyyrikki_standalone"] = r1
    if r1 and r2:
        s.check("deterministic: identical finding IDs across two runs",
                sorted(f["finding_id"] for f in r1["findings"]) == sorted(f["finding_id"] for f in r2["findings"]))
        s.check("identical findings apart from per-run fields", stable(r1) == stable(r2))
    p = run.exec(nyy, "scan", run.ws / BENIGN_FILE)
    run.save("3.3-nyyrikki-benign.json", p.stdout)
    b = load_agent(p.stdout, s, "benign")
    s.check("benign: status ok, 0 findings", b and b["status"] == "ok" and b["findings_total"] == 0)
    p = run.exec(nyy, "scan", run.ws / ATTACK_FILE, "--text")
    run.save("3.4-nyyrikki-attack.txt", p.stdout)
    s.check("text report shows the generic source, not the input path",
            b"Source:          security-event-export" in p.stdout, "")


def stage4(run: Run, ctx: dict) -> None:
    s = run.stage("4. Borealis Node orchestration")
    bn, cfg = run.args.borealis_node, run.ws / "node-main.json"
    reports = []
    for i in (1, 2):
        p = run.exec(bn, "run", "--config", cfg, "--json")
        run.save(f"4.{i}-node-run{i}.json", p.stdout)
        s.check(f"node run {i}: exit 0 (outcome ok)", p.returncode == 0, text(p)[-200:])
        reports.append(load_node(p.stdout, s, f"node run {i}"))
    n1, n2 = reports
    if n1:
        s.check("node outcome ok and report complete", n1["outcome"] == "ok" and n1["complete"] is True)
        by_name = {a["config_name"]: a for a in n1["agents"]}
        for name, expected_total in (("nyyrikki", 5), ("ilmarinen", 3)):
            a = by_name.get(name)
            rep = a and a["report"]
            s.check(f"{name}: embedded, valid, attributed to the configured agent",
                    bool(rep) and a["validation"]["result"] == "valid" and rep["agent"]["name"] == a["expected_name"] == name)
            s.check(f"{name}: {expected_total} findings", bool(rep) and rep["findings_total"] == expected_total)
            standalone = ctx.get(f"{name}_standalone")
            s.check(f"{name}: embedded report equals the standalone report (ignoring per-run fields)",
                    bool(rep) and standalone is not None and stable(rep) == stable(standalone))
    if n1 and n2:
        ids = lambda n: sorted(f["finding_id"] for a in n["agents"] if a["report"] for f in a["report"]["findings"])  # noqa: E731
        s.check("deterministic: identical finding IDs across two node runs", ids(n1) == ids(n2) and len(ids(n1)) == 8)
    p = run.exec(bn, "run", "--config", cfg)
    run.save("4.3-node.txt", p.stdout)
    out = p.stdout.decode("utf-8", "replace")
    s.check("text view: findings summary separate from outcome",
            "Outcome: ok" in out and "Findings: 8 (3 high, 4 medium, 1 low)" in out
            and "does not mean nothing was found" in out)
    s.check("text view: evidence references shown", "evidence: windows-security:record:2014" in out
            and "evidence: file:testapp:README.txt" in out)


def stage5(run: Run, ctx: dict) -> None:
    s = run.stage("5. Failure handling")
    bn, ws = run.args.borealis_node, run.ws

    def node_run(name: str, agents: list[dict]) -> tuple[int, dict | None]:
        cfg = write_node_config(run, name, agents)
        p = run.exec(bn, "run", "--config", cfg, "--json")
        run.save(f"5-{name}.json", p.stdout)
        return p.returncode, load_node(p.stdout, s, name)

    def ilm_entry(config_name: str, baseline: Path, *extra) -> dict:
        cfg = ws / f"ilmarinen-{config_name}.json"
        cfg.write_text(json.dumps({"roots": [{"id": "testapp", "path": str(ws / "monitored"), "recursive": True,
                                              "exclude": []}], "baseline": str(baseline)}))
        return {**ctx["ilm"], "config_name": config_name, "args": ["check", "--config", str(cfg), *extra]}

    # 5.1 missing agent
    missing = {**ctx["ilm"], "executable": str(ws / "not-installed" / ("ilmarinen.exe" if WINDOWS else "ilmarinen"))}
    code, n = node_run("missing-agent", [ctx["nyy"], missing])
    if n:
        a = {x["config_name"]: x for x in n["agents"]}
        s.check("missing agent: node degraded, exit 1", n["outcome"] == "degraded" and code == 1)
        s.check("missing agent: ilmarinen failed with launch_error not-found",
                a["ilmarinen"]["outcome"] == "failed" and a["ilmarinen"]["execution"]["launch_error"] == "not-found")
        s.check("missing agent: Nyyrikki's 5 findings retained",
                a["nyyrikki"]["report"] is not None and a["nyyrikki"]["report"]["findings_total"] == 5)

    original = json.loads(ctx["baseline"].read_text())

    # 5.2 corrupted copy (embedded digest NOT recomputed)
    corrupt = json.loads(json.dumps(original))
    corrupt["entries"][0]["sha256"] = "0" * 64
    (ws / "fail").mkdir()
    (ws / "fail" / "baseline-corrupt.json").write_bytes(std.canonical_json(corrupt) + b"\n")
    code, n = node_run("corrupted-baseline", [ctx["nyy"], ilm_entry("ilmarinen-corrupt", ws / "fail" / "baseline-corrupt.json")])
    if n:
        a = {x["config_name"]: x for x in n["agents"]}["ilmarinen-corrupt"]
        rep = a["report"]
        s.check("corrupted baseline: valid error report with baseline-integrity-failure, embedded",
                rep is not None and rep["status"] == "error" and rep["findings"][0]["rule_id"] == "baseline-integrity-failure")
        s.check("corrupted baseline: agent failed and node degraded (not mistaken for a clean scan)",
                a["outcome"] == "failed" and n["outcome"] == "degraded" and code == 1)

    # 5.3 rewritten copy: hide the app.conf change and RECOMPUTE the embedded digest
    tampered = json.loads(json.dumps(original))
    app = ws / "monitored" / "config" / "app.conf"
    for e in tampered["entries"]:
        if e["ref"] == "file:testapp:config/app.conf":
            e["sha256"], e["size"] = sha256_file(app), app.stat().st_size
    tampered.pop("digest")
    tampered["digest"] = hashlib.sha256(std.canonical_json(tampered)).hexdigest()
    (ws / "fail" / "baseline-tampered.json").write_bytes(std.canonical_json(tampered) + b"\n")
    tampered_path = ws / "fail" / "baseline-tampered.json"
    code, n = node_run("rewritten-baseline", [
        ilm_entry("tampered-no-digest", tampered_path),
        ilm_entry("tampered-with-digest", tampered_path, "--expected-digest", ctx["digest"]),
        ilm_entry("original-with-digest", ctx["baseline"], "--expected-digest", ctx["digest"]),
    ])
    if n:
        a = {x["config_name"]: x for x in n["agents"]}
        no_digest = a["tampered-no-digest"]["report"]
        hidden = no_digest is not None and no_digest["status"] == "ok" and not any(
            f["rule_id"] == "file-changed" for f in no_digest["findings"])
        s.check("rewritten baseline WITHOUT expected digest hides the change (documented limitation reproduced)", hidden)
        with_digest = a["tampered-with-digest"]["report"]
        s.check("rewritten baseline WITH expected digest: baseline-integrity-failure",
                with_digest is not None and with_digest["status"] == "error"
                and with_digest["findings"][0]["rule_id"] == "baseline-integrity-failure")
        orig = a["original-with-digest"]["report"]
        s.check("original baseline WITH expected digest: ok, and the real change is reported",
                orig is not None and orig["status"] == "ok"
                and any(f["rule_id"] == "file-changed" for f in orig["findings"]))
    s.check("original baseline unchanged throughout", sha256_file(ctx["baseline"]) == ctx["baseline_sha"])


def privacy(run: Run) -> None:
    s = run.stage("Privacy of saved evidence")
    secrets = {str(run.ws), str(run.ws).replace("\\", "/"), str(run.ws).replace("\\", "\\\\"),
               os.path.expanduser("~"), ATTACK_FILE, BENIGN_FILE}
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = ""
    if len(user) >= 3 and user != "root":  # "root" is also the report's scope kind
        secrets.add(user)
    elif user == "root":
        s.notes.append("user name 'root' not searched by substring (it is also a report field value)")
    for path in sorted(run.evidence.iterdir()):
        content = path.read_bytes().decode("utf-8", "replace").lower()
        leaked = sorted(x for x in secrets if x and len(x) >= 3 and x.lower() in content)
        s.check(f"{path.name}: no workspace path, home path, user name or input file name", not leaked,
                "found: " + ", ".join("<user name>" if x == user else "<path>" if os.sep in x or "/" in x else x
                                      for x in leaked))


# --- main --------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for name in ("nyyrikki", "ilmarinen", "borealis-node"):
        parser.add_argument(f"--{name}", required=True, help=f"absolute path to the installed {name} executable")
    parser.add_argument("--out", required=True, help="evidence directory to create (must not exist)")
    parser.add_argument("--keep-workspace", action="store_true", help="keep the temporary workspace for debugging")
    args = parser.parse_args()
    args.borealis_node = getattr(args, "borealis_node")
    for name in ("nyyrikki", "ilmarinen", "borealis_node"):
        value = getattr(args, name)
        if not os.path.isabs(value) or not os.path.isfile(value):
            print(f"setup error: --{name.replace('_', '-')} must be an absolute path to an existing file", file=sys.stderr)
            return 2
    evidence = Path(args.out).resolve()
    if evidence.exists():
        print("setup error: --out must not exist (evidence is never overwritten)", file=sys.stderr)
        return 2
    evidence.mkdir(parents=True)
    workspace = Path(tempfile.mkdtemp(prefix="borealis-itest-"))
    run = Run(args, workspace, evidence)
    crashed = None
    ctx: dict = {}
    try:
        ctx.update(setup(run))
        for stage_fn in (stage1, stage2, stage3, stage4, stage5):
            try:
                stage_fn(run, ctx)
            except Exception as exc:  # noqa: BLE001 - a crashing stage is a failed stage, never a pass
                run.stage(stage_fn.__name__).check("stage ran to completion", False, f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001
        crashed = f"{type(exc).__name__}: {exc}"

    # Failure details can quote tool output; redact local paths and the user name before saving.
    def redact(value: str) -> str:
        for secret, label in ((str(workspace), "<workspace>"), (str(workspace).replace("\\", "/"), "<workspace>"),
                              (os.path.expanduser("~"), "<home>")):
            value = value.replace(secret, label)
        user = getpass.getuser() if hasattr(getpass, "getuser") else ""
        if len(user) >= 3 and user != "root":
            value = value.replace(user, "<user>")
        return value

    for stage in run.stages:
        stage.checks = [(d, ok, redact(det)) for d, ok, det in stage.checks]
    crashed = redact(crashed) if crashed else None

    def render(all_ok: bool) -> tuple[str, str]:
        lines = ["Borealis synthetic integration test", "===================================",
                 f"Platform: {platform.system()} {platform.release()} ({platform.machine()}), "
                 f"Python {platform.python_version()}",
                 f"Agents: nyyrikki {ctx.get('nyyrikki_version', '?')}, ilmarinen {ctx.get('ilmarinen_version', '?')}", ""]
        for stage in run.stages:
            passed = sum(ok for _, ok, _ in stage.checks)
            lines.append(f"[{'PASS' if stage.passed else 'FAIL'}] {stage.name} ({passed}/{len(stage.checks)} checks)")
            lines += [f"    FAILED: {d}" + (f" -- {det}" if det else "") for d, ok, det in stage.checks if not ok]
            lines += [f"    note: {note}" for note in stage.notes]
        if crashed:
            lines.append(f"[FAIL] setup: {crashed}")
        lines += ["", f"OVERALL: {'PASS' if all_ok else 'FAIL'}",
                  "Evidence saved in the --out directory (synthetic data only).",
                  "A pass shows the components work together as designed on synthetic data on this machine.",
                  "It does not show detection of real attacks, production readiness or security assurance."]
        as_json = json.dumps({
            "overall": "pass" if all_ok else "fail",
            "platform": {"system": platform.system(), "release": platform.release(), "python": platform.python_version()},
            "agents": {"nyyrikki": ctx.get("nyyrikki_version"), "ilmarinen": ctx.get("ilmarinen_version")},
            "stages": [{"name": st.name, "passed": st.passed, "notes": st.notes,
                        "checks": [{"check": d, "passed": ok, "detail": det} for d, ok, det in st.checks]}
                       for st in run.stages],
        }, indent=2)
        return chr(10).join(lines) + chr(10), as_json

    # 1. Write a preliminary summary, 2. privacy-check every saved file (summaries included),
    # 3. write the final summary with the privacy result.
    summary, as_json = render(crashed is None and all(stage.passed for stage in run.stages))
    (evidence / "summary.txt").write_text(summary, encoding="utf-8")
    (evidence / "summary.json").write_text(as_json, encoding="utf-8")
    privacy(run)
    all_ok = crashed is None and all(stage.passed for stage in run.stages)
    summary, as_json = render(all_ok)
    (evidence / "summary.txt").write_text(summary, encoding="utf-8")
    (evidence / "summary.json").write_text(as_json, encoding="utf-8")
    if not args.keep_workspace:
        shutil.rmtree(workspace, ignore_errors=True)
    sys.stdout.write(summary)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
