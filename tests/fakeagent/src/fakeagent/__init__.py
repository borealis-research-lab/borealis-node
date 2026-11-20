"""Test-only fake agent. Behaviour: `describe` (controlled by FAKE_DESCRIBE_NAME /
FAKE_DESCRIBE_MODE env vars) or `run <mode> [arg]`. Produces synthetic data only."""

import hashlib
import json
import os
import subprocess
import sys
import time

NAME = "fake"


def _finding(name, rule, ref, severity="medium", details=None):
    digest = hashlib.sha256(ref.encode()).hexdigest()
    fid = name + ":" + rule + ":" + hashlib.sha256((rule + "\n" + digest).encode()).hexdigest()[:16]
    item = {"ref": ref}
    if details is not None:
        item["details"] = details
    return {"finding_id": fid, "created_at": "2026-11-20T12:00:00Z", "rule_id": rule, "severity": severity,
            "observation": "synthetic", "assessment": "synthetic", "recommendation": "none", "limitations": "test",
            "evidence": [item], "evidence_total": 1, "evidence_refs_digest": digest}


def report(name=NAME, status="ok", findings=(), errors=()):
    errors = list(errors)
    counts = {}
    for e in errors:
        counts[e["code"]] = counts.get(e["code"], 0) + 1
    return {"standard": "borealis-agent-report/1", "agent": {"name": name, "version": "0.0.1"},
            "run": {"id": "3f2b8c1e-5d4a-4b6f-9e2d-1a2b3c4d5e6f", "started_at": "2026-11-20T12:00:00Z",
                    "finished_at": "2026-11-20T12:00:01Z"},
            "source": {"type": "synthetic", "description": "test", "scope": []},
            "status": status, "errors": errors, "errors_total": len(errors), "error_counts": counts,
            "findings": list(findings), "findings_total": len(findings)}


def emit(obj):
    sys.stdout.write(json.dumps(obj))


def main():
    args = sys.argv[1:]
    if args == ["describe"]:
        mode = os.environ.get("FAKE_DESCRIBE_MODE", "ok")
        if mode == "crash":
            sys.exit(5)
        if mode == "garbage":
            sys.stdout.write("not json")
            return 0
        emit({"standard": "borealis-agent-report/1", "name": os.environ.get("FAKE_DESCRIBE_NAME", NAME),
              "version": "0.0.1", "responsibility": "test agent", "personal_data": []})
        return 0
    mode = args[1] if len(args) > 1 else "ok"
    f = _finding(NAME, "thing-found", "synthetic:1")
    if mode == "ok":
        emit(report(findings=[f]))
    elif mode == "empty":
        emit(report())
    elif mode == "partial":
        emit(report(status="partial", findings=[f], errors=[{"code": "unreadable", "message": "x", "ref": "synthetic:2"}]))
    elif mode == "error-with-finding":
        emit(report(status="error", findings=[_finding(NAME, "integrity", "synthetic:b", "high")],
                    errors=[{"code": "integrity", "message": "reference data tampered"}]))
    elif mode == "invalid-json":
        sys.stdout.write("{not json")
    elif mode == "duplicate-keys":
        sys.stdout.write(json.dumps(report())[:-1] + ', "status": "ok"}')
    elif mode == "nan":
        sys.stdout.write(json.dumps(report()).replace('"errors_total": 0', '"errors_total": NaN'))
    elif mode == "unknown-field":
        r = report()
        r["confidence"] = 0
        emit(r)
    elif mode == "partial-without-errors":
        emit(report(status="partial"))
    elif mode == "counts-mismatch":
        r = report(status="partial", errors=[{"code": "unreadable", "message": "x"}])
        r["error_counts"] = {"unreadable": 2}
        emit(r)
    elif mode == "other-codes-as-code":
        emit(report(status="partial", errors=[{"code": "other-codes", "message": "x"}]))
    elif mode == "duplicate-finding-ids":
        emit(report(findings=[f, dict(f)]))
    elif mode == "wrong-name":
        emit(report(name="impostor", findings=[_finding("impostor", "thing-found", "synthetic:1")]))
    elif mode == "ansi":
        sys.stderr.write("\x1b[31mRED\x1b[0m \x1b]0;title\x07 and a bell \x07")
        emit(report())
        return 3
    elif mode == "huge":
        sys.stdout.write("x" * (11 * 1024 * 1024))
    elif mode == "timeout":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        with open(args[2], "w") as handle:
            handle.write(str(child.pid))
        time.sleep(300)
    elif mode == "crash":
        sys.stderr.write("Traceback: something failed in " + os.path.expanduser("~") + "\n")
        return 3
    elif mode == "large":
        size = int(args[2])
        blob = "z" * 1000
        findings = [_finding(NAME, "thing-found", f"synthetic:{i}", details={"blob": blob}) for i in range(size)]
        emit(report(findings=findings))
    elif mode == "marker":
        with open(args[2], "w") as handle:
            handle.write("ran")
        emit(report())
    return 0
