"""Borealis Node tests. Uses the test-only fake agent console script (tests/fakeagent,
installed into the test environment) and synthetic data only."""

import json
import os
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "standards"))
import check_report  # noqa: E402  (vendored reference checker, test-only)

from borealis_node import config as config_mod  # noqa: E402
from borealis_node import node, procexec  # noqa: E402
from borealis_node.cli import main  # noqa: E402

WINDOWS = os.name == "nt"
FAKE = Path(sys.executable).parent / ("fake-agent.exe" if WINDOWS else "fake-agent")
pytestmark = pytest.mark.skipif(not FAKE.exists(), reason="install tests/fakeagent: pip install -e tests/fakeagent")


def agent(name, mode, *extra, timeout=60, expected="fake", exe=None):
    return {"config_name": name, "expected_name": expected, "executable": str(exe or FAKE),
            "args": ["run", mode, *map(str, extra)], "timeout_s": timeout}


def write_config(tmp_path, agents):
    path = tmp_path / "node.json"
    path.write_text(json.dumps({"agents": agents}), encoding="utf-8")
    return path


def run_node(capsys, tmp_path, agents, *flags):
    cfg = write_config(tmp_path, agents)
    code = main(["run", "--config", str(cfg), "--json", *flags])
    out, err = capsys.readouterr()
    data = out.encode("utf-8")
    report = check_report.strict_loads(data)
    assert check_report.validate_node_report(report, len(data)) == [], "node report must conform"
    return code, report, err


def entry(report, name):
    return next(a for a in report["agents"] if a["config_name"] == name)


# --- outcomes ---------------------------------------------------------------------------------


@pytest.mark.parametrize("mode, outcome, validation", [
    ("ok", "ok", "valid"),
    ("empty", "ok", "valid"),
    ("partial", "degraded", "valid"),
    ("error-with-finding", "failed", "valid"),
    ("invalid-json", "failed", "invalid"),
    ("duplicate-keys", "failed", "invalid"),
    ("nan", "failed", "invalid"),
    ("unknown-field", "failed", "invalid"),
    ("partial-without-errors", "failed", "invalid"),
    ("counts-mismatch", "failed", "invalid"),
    ("other-codes-as-code", "failed", "invalid"),
    ("duplicate-finding-ids", "failed", "invalid"),
    ("wrong-name", "failed", "invalid"),
])
def test_single_agent_outcomes(capsys, tmp_path, mode, outcome, validation):
    code, report, _ = run_node(capsys, tmp_path, [agent("a", mode)])
    e = entry(report, "a")
    assert e["outcome"] == outcome and e["validation"]["result"] == validation
    assert code == (0 if outcome == "ok" else 1)
    if validation == "invalid":
        assert e["report"] is None and e["validation"]["problems_total"] >= 1
        assert all(p.isascii() and len(p) <= 300 for p in e["validation"]["problems"])


def test_valid_error_report_is_embedded_and_its_findings_shown(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "error-with-finding")])
    e = entry(report, "a")
    assert e["report_embedding"] == "embedded" and e["report"]["findings"][0]["rule_id"] == "integrity"


def test_findings_are_embedded_unchanged(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "ok")])
    import fakeagent

    expected = fakeagent.report(findings=[fakeagent._finding("fake", "thing-found", "synthetic:1")])
    assert entry(report, "a")["report"]["findings"] == expected["findings"]


@pytest.mark.parametrize("modes, node_outcome", [
    (["ok", "ok"], "ok"),
    (["ok", "partial"], "degraded"),
    (["ok", "invalid-json"], "degraded"),
    (["partial", "crash"], "degraded"),
    (["error-with-finding", "invalid-json"], "failed"),
    (["error-with-finding", "error-with-finding"], "failed"),
])
def test_node_outcome_aggregation(capsys, tmp_path, modes, node_outcome):
    _, report, _ = run_node(capsys, tmp_path, [agent(f"a{i}", m) for i, m in enumerate(modes)])
    assert report["outcome"] == node_outcome


def test_failed_agent_does_not_hide_others(capsys, tmp_path):
    missing = tmp_path / "nope.exe"
    _, report, _ = run_node(capsys, tmp_path, [agent("gone", "ok", exe=missing), agent("works", "ok")])
    assert entry(report, "gone")["execution"]["launch_error"] == "not-found"
    assert entry(report, "works")["outcome"] == "ok" and report["outcome"] == "degraded"


# --- identity -----------------------------------------------------------------------------


def test_describe_mismatch_is_rejected(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_DESCRIBE_NAME", "someone-else")
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "ok")])
    e = entry(report, "a")
    assert e["outcome"] == "failed" and e["execution"]["launch_error"] == "describe-mismatch"


@pytest.mark.parametrize("mode", ["crash", "garbage"])
def test_describe_failures(capsys, tmp_path, monkeypatch, mode):
    monkeypatch.setenv("FAKE_DESCRIBE_MODE", mode)
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "ok")])
    assert entry(report, "a")["execution"]["launch_error"] == "describe-failed"


def test_agents_command(capsys, tmp_path, monkeypatch):
    cfg = write_config(tmp_path, [agent("good", "ok"), agent("missing", "ok", exe=tmp_path / "x.exe")])
    code = main(["agents", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert "good" in out and "compatible" in out and "missing" in out and code == 1


# --- execution limits and isolation -------------------------------------------------------------


def test_too_much_output_is_killed(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "huge")])
    ex = entry(report, "a")["execution"]
    assert ex["output_too_large"] and ex["killed"] and entry(report, "a")["outcome"] == "failed"


def _alive(pid: int) -> bool:
    if WINDOWS:
        import ctypes

        k32 = ctypes.WinDLL("kernel32")
        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return code.value == 259
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    with open(f"/proc/{pid}/stat") as handle:  # a reaped-later zombie is not running
        return handle.read().split()[2] != "Z"


def test_timeout_kills_agent_and_grandchild(capsys, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    _, report, _ = run_node(capsys, tmp_path, [agent("slow", "timeout", pidfile, timeout=3)])
    ex = entry(report, "slow")["execution"]
    assert ex["timed_out"] and ex["killed"] and entry(report, "slow")["outcome"] == "failed"
    time.sleep(1)
    assert not _alive(int(pidfile.read_text())), "grandchild survived the timeout"


@pytest.mark.skipif(not WINDOWS, reason="Job Objects are Windows-only")
def test_isolation_failure_fails_closed_before_agent_runs(capsys, tmp_path, monkeypatch):
    marker = tmp_path / "ran.marker"
    real_run = procexec.run

    def run_with_failing_job(executable, args, timeout, cwd=None):
        procexec.FAIL_JOB_ASSIGNMENT = args != ["describe"]  # let describe pass, fail the real run
        try:
            return real_run(executable, args, timeout, cwd)
        finally:
            procexec.FAIL_JOB_ASSIGNMENT = False

    monkeypatch.setattr(procexec, "run", run_with_failing_job)
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "marker", marker)])
    assert entry(report, "a")["execution"]["launch_error"] == "isolation-failed"
    time.sleep(0.5)
    assert not marker.exists(), "agent code ran although isolation failed"


# --- diagnostics and terminal safety --------------------------------------------------------------


def test_diagnostics_excluded_by_default(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "crash")])
    assert entry(report, "a")["diagnostic"] is None


def test_diagnostics_redacted_when_requested(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "crash")], "--include-diagnostics")
    diag = entry(report, "a")["diagnostic"]
    assert "Traceback" in diag and "<home>" in diag
    assert os.path.expanduser("~").lower() not in diag.lower()


def test_terminal_output_strips_escape_sequences(capsys, tmp_path):
    cfg = write_config(tmp_path, [agent("a", "ansi")])
    main(["run", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out


# --- size budget, sidecars and the 64 MiB guarantee -------------------------------------------------


def test_over_budget_report_is_omitted_with_summary_and_sidecar(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(node, "EMBED_BUDGET", 200_000)  # small budget to keep the test fast
    out = tmp_path / "out" / "node-report.json"
    out.parent.mkdir()
    code, report, _ = run_node(capsys, tmp_path, [agent("big", "large", 400), agent("small", "ok")],
                               "--out", str(out))
    big = entry(report, "big")
    assert big["report_embedding"] == "omitted-for-size" and big["report"] is None
    assert big["outcome"] == "ok" and report["complete"] is False
    summary = big["report_summary"]
    assert summary["saved_as"] == "big.json" and "/" not in summary["saved_as"] and "\\" not in summary["saved_as"]
    assert summary["findings_total"] == 400 and len(summary["finding_ids"]) == 200
    saved = json.loads((out.parent / "node-report.json.agents" / "big.json").read_text())
    assert check_report.validate_agent_report(saved) == []
    assert entry(report, "small")["report_embedding"] == "embedded"


def test_out_never_overwrites(capsys, tmp_path):
    cfg = write_config(tmp_path, [agent("a", "ok")])
    out = tmp_path / "r.json"
    out.write_text("keep")
    assert main(["run", "--config", str(cfg), "--out", str(out)]) == 2
    assert out.read_text() == "keep"
    sidecars = tmp_path / "s.json.agents"
    sidecars.mkdir()
    assert main(["run", "--config", str(cfg), "--out", str(tmp_path / "s.json")]) == 2
    capsys.readouterr()


def test_32_maximum_size_reports_stay_within_64_mib(tmp_path):
    import fakeagent

    blob = "z" * 9000
    big = fakeagent.report(findings=[fakeagent._finding("fake", "thing-found", f"synthetic:{i}",
                                                        details={"blob": blob}) for i in range(1000)])
    assert len(json.dumps(big).encode()) > 8 * 1024 * 1024  # each close to the 10 MiB agent limit
    entries = []
    for i in range(32):
        e, _ = {"config_name": f"a{i:02d}", "expected_name": "fake", "outcome": "ok",
                "execution": {"started_at": "2026-11-20T12:00:00Z", "finished_at": "2026-11-20T12:00:01Z",
                              "exit_code": 0, "timed_out": False, "killed": False, "stdout_bytes": 1,
                              "output_too_large": False, "launch_error": None},
                "validation": {"result": "valid", "problems": [], "problems_total": 0}, "diagnostic": None,
                "report_embedding": "embedded", "report": big, "report_summary": None}, None
        entries.append(e)
    report = node.build(entries, time.time(), time.time(), None)
    data = node.serialise(report).encode("utf-8")
    assert len(data) <= node.MAX_NODE_BYTES
    assert all(a["report_embedding"] == "omitted-for-size" for a in report["agents"])
    assert check_report.validate_node_report(check_report.strict_loads(data), len(data)) == []


def test_maximum_envelope_fits_reserve():
    envelope = check_report.max_envelope_node_report()
    assert len(json.dumps(envelope, ensure_ascii=False).encode()) <= node.ENVELOPE_RESERVE


# --- configuration -----------------------------------------------------------------------------------


@pytest.mark.parametrize("change", [
    {"config_name": "../x"}, {"config_name": "a/b"}, {"config_name": "A"}, {"config_name": "x" * 33},
    {"executable": "fake-agent"}, {"timeout_s": 0}, {"timeout_s": True}, {"args": "run ok"},
    {"expected_name": "Bad Name"}, {"unexpected": 1},
])
def test_config_refusals(capsys, tmp_path, change):
    item = {**agent("a", "ok"), **change}
    cfg = write_config(tmp_path, [item])
    assert main(["run", "--config", str(cfg)]) == 2
    assert capsys.readouterr().out == ""


def test_duplicate_config_names_refused(capsys, tmp_path):
    cfg = write_config(tmp_path, [agent("a", "ok"), agent("a", "ok")])
    assert main(["run", "--config", str(cfg)]) == 2


def test_too_many_agents_refused(capsys, tmp_path):
    cfg = write_config(tmp_path, [agent(f"a{i}", "ok") for i in range(33)])
    assert main(["run", "--config", str(cfg)]) == 2


def test_validator_agrees_with_reference_vectors():
    from borealis_node.validate import validate_agent_report

    vectors = check_report.strict_loads((HERE / "standards" / "test-vectors-v1.json").read_bytes())
    for v in vectors["reports"]:
        if v["kind"] == "agent":
            assert (validate_agent_report(v["report"]) == []) == v["valid"], v["name"]


def _paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, prefix + (i,))


@pytest.mark.parametrize("example", ["agent-report-nyyrikki.json", "agent-report-ilmarinen-partial.json"])
def test_validator_never_crashes_on_mutated_agent_output(example):
    """Agent output is untrusted: the Node must report problems, never crash."""
    import copy

    from borealis_node.validate import validate_agent_report

    vectors = check_report.strict_loads((HERE / "standards" / "test-vectors-v1.json").read_bytes())
    base = next(v["report"] for v in vectors["reports"]
                if v["name"] == ("valid-agent-ok" if "nyyrikki" in example else "valid-agent-partial"))
    replacements = [None, 1, "x", [], {}, True, -5, chr(0xE4) * 600, [1, [2]], {"a": {}}, chr(0xD800),
                    "x" + chr(10), "DELETE"]
    for path in (p for p in _paths(base) if p):
        for replacement in replacements:
            mutated = copy.deepcopy(base)
            parent = mutated
            for key in path[:-1]:
                parent = parent[key]
            if replacement == "DELETE":
                if not isinstance(parent, dict):
                    continue
                del parent[path[-1]]
            else:
                parent[path[-1]] = replacement
            problems = validate_agent_report(mutated)
            assert all(p.isascii() and len(p) <= 300 for p in problems)


# --- findings summary in the text view (presentation only) ----------------------------------------


def run_text(capsys, tmp_path, agents):
    cfg = write_config(tmp_path, agents)
    code = main(["run", "--config", str(cfg)])
    return code, capsys.readouterr().out


def test_text_summary_separates_findings_from_outcome(capsys, tmp_path):
    code, out = run_text(capsys, tmp_path, [agent("a", "ok"), agent("b", "error-with-finding")])
    assert "Outcome: degraded" in out and code == 1  # outcome and exit code unchanged
    assert "Findings: 2 (1 high, 1 medium, 0 low)" in out
    assert "the outcome describes whether the agents' analysis completed" in out


def test_text_summary_warns_that_ok_is_not_clean(capsys, tmp_path):
    code, out = run_text(capsys, tmp_path, [agent("a", "ok")])
    assert "Outcome: ok" in out and code == 0
    assert "Findings: 1 (0 high, 1 medium, 0 low)" in out
    assert "does not mean nothing was found" in out


def test_text_summary_with_no_findings(capsys, tmp_path):
    _, out = run_text(capsys, tmp_path, [agent("a", "empty")])
    assert "Findings: 0 (0 high, 0 medium, 0 low)" in out
    assert "does not mean the system is safe" in out


def test_text_summary_reports_unknown_agents(capsys, tmp_path):
    _, out = run_text(capsys, tmp_path, [agent("works", "ok"), agent("gone", "ok", exe=tmp_path / "missing.exe")])
    assert "unknown for: gone (no valid report)" in out


def test_text_summary_counts_omitted_reports(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(node, "EMBED_BUDGET", 200_000)
    _, out = run_text(capsys, tmp_path, [agent("big", "large", 400)])
    assert "Findings: 400 (0 high, 400 medium, 0 low)" in out


def test_json_report_is_unchanged_by_the_summary(capsys, tmp_path):
    _, report, _ = run_node(capsys, tmp_path, [agent("a", "ok")])
    assert set(report) == {"standard", "node", "run", "outcome", "complete", "agents"}


# --- agent versions and evidence references (presentation only) -------------------------------------


def test_agents_command_shows_validated_name_and_version(capsys, tmp_path, monkeypatch):
    cfg = write_config(tmp_path, [agent("good", "ok"), agent("missing", "ok", exe=tmp_path / "x.exe")])
    main(["agents", "--config", str(cfg)])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["good", "compatible", "fake", "0.0.1"]
    assert lines[1].split() == ["missing", "missing"]  # nothing claimed for an agent that wasn't run
    monkeypatch.setenv("FAKE_DESCRIBE_NAME", "impostor")
    main(["agents", "--config", str(cfg)])
    first = capsys.readouterr().out.splitlines()[0]
    assert first.split() == ["good", "incompatible"]  # an unvalidated identity is never displayed


def test_text_view_shows_agent_evidence_references(capsys, tmp_path):
    cfg = write_config(tmp_path, [agent("a", "ok")])
    main(["run", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert "[MEDIUM] thing-found: synthetic" in out
    assert "      evidence: synthetic:1" in out


def test_evidence_references_are_capped_with_a_count():
    finding = {"evidence": [{"ref": f"windows-security:record:{2000 + i}"} for i in range(500)], "evidence_total": 600}
    assert node.evidence_refs(finding) == (
        "windows-security:record:2000, windows-security:record:2001, windows-security:record:2002 (+597 more)")
    single = {"evidence": [{"ref": "file:docs:a.txt"}], "evidence_total": 1}
    assert node.evidence_refs(single) == "file:docs:a.txt"


def test_evidence_references_are_rendered_safely():
    finding = {"evidence": [{"ref": "x:evil\x1b[31m\nFinding 9"}], "evidence_total": 1}
    rendered = node.evidence_refs(finding)
    assert "\x1b" not in rendered and "\n" not in rendered
