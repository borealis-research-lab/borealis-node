"""Strict JSON parsing and validation of borealis-agent-report/1 (structure and every invariant),
implemented independently. Agent output is untrusted data: it is only parsed and checked,
never interpreted as instructions. Problems are short, ASCII, Node-generated messages that
never quote agent-supplied text.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Any

AGENT_STANDARD = "borealis-agent-report/1"
MAX_AGENT_REPORT_BYTES = 10 * 1024 * 1024
MAX_INT = 2**53 - 1
RESERVED = ("findings-truncated", "evidence-truncated-for-size", "details-omitted-for-size", "report-too-large")
RANK = {"high": 0, "medium": 1, "low": 2}

AGENT_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")
CODE = re.compile(r"[a-z][a-z0-9-]{0,63}")
TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
NAMESPACE = re.compile(r"[a-z][a-z0-9-]{0,63}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
HEX64 = re.compile(r"[0-9a-f]{64}")
PRINTABLE = re.compile(r"[\x20-\x7e]+")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
TEXT_FORBIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# `source` must not contain absolute filesystem paths (drive letters, UNC, common POSIX homes).
ABSOLUTE_PATH = re.compile(r"(?:\b[A-Za-z]:[\\/])|(?:\\\\[^\\\s]+\\)|(?:(?:^|\s)/(?:home|Users|root)/)")
SURROGATE = re.compile("[\ud800-\udfff]")


class InvalidJson(ValueError):
    pass


# --- strict JSON ---------------------------------------------------------------------------


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InvalidJson("duplicate object key")
        out[key] = value
    return out


def _const(name):
    raise InvalidJson("non-standard JSON value")


def _float(text):
    raise InvalidJson("floats are not permitted")


def _int(text):
    if len(text.lstrip("-")) > len(str(MAX_INT)) or abs(int(text)) > MAX_INT:
        raise InvalidJson("integer out of range")
    return int(text)


def strict_loads(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise InvalidJson("byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidJson("not valid UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_const, parse_float=_float, parse_int=_int)
    except InvalidJson:
        raise
    except (ValueError, RecursionError):
        raise InvalidJson("not a single valid JSON value") from None
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if SURROGATE.search(item):
                raise InvalidJson("unpaired surrogate")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
    return value


# --- helpers -------------------------------------------------------------------------------


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, message: str) -> None:
        self.items.append(f"{path}: {message}".encode("ascii", "replace").decode("ascii")[:300])


def _is(value, regex) -> bool:
    return isinstance(value, str) and regex.fullmatch(value) is not None


def _int_ok(value, minimum=0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _keys(p: Problems, obj, path: str, required: set, optional: set = frozenset()) -> bool:
    if not isinstance(obj, dict):
        p.add(path, "must be an object")
        return False
    missing = required - obj.keys()
    for key in sorted(missing):
        p.add(path, "missing required field")
    if obj.keys() - required - optional:
        p.add(path, "unknown field present")
    return not missing


def _text(p: Problems, value, path: str, limit: int) -> None:
    if not isinstance(value, str) or len(value) > limit or TEXT_FORBIDDEN.search(value) or SURROGATE.search(value):
        p.add(path, f"must be plain text of at most {limit} characters")


def _ts(p: Problems, value, path: str) -> datetime | None:
    if not _is(value, TIMESTAMP):
        p.add(path, "must be a UTC timestamp ending in Z")
        return None
    try:
        return datetime.fromisoformat(value[:-1])
    except ValueError:
        p.add(path, "invalid date")
        return None


def _ref_ok(ref) -> bool:
    if not isinstance(ref, str):
        return False
    namespace, sep, value = ref.partition(":")
    return (bool(sep) and NAMESPACE.fullmatch(namespace) is not None and 1 <= len(value) <= 1000
            and not CONTROL.search(value) and not SURROGATE.search(value)
            and unicodedata.normalize("NFC", value) == value)


def canonical_refs(refs: list[str]) -> list[str]:
    return sorted({unicodedata.normalize("NFC", r) for r in refs})


def refs_digest(refs: list[str]) -> str:
    return hashlib.sha256("\n".join(canonical_refs(refs)).encode("utf-8")).hexdigest()


def finding_id(agent: str, rule: str, digest: str) -> str:
    return agent + ":" + rule + ":" + hashlib.sha256((rule + "\n" + digest).encode("utf-8")).hexdigest()[:16]


def _ordered(errors: list[dict]) -> list[dict]:
    reserved = [e for c in RESERVED for e in errors if e.get("code") == c]
    rest = sorted((e for e in errors if e.get("code") not in RESERVED),
                  key=lambda e: (e["code"], e.get("ref", ""), e["message"]))
    return reserved + rest


# --- agent report ----------------------------------------------------------------------------


def validate_agent_report(report: Any, size: int | None = None) -> list[str]:
    p = Problems()
    if size is not None and size > MAX_AGENT_REPORT_BYTES:
        p.add("$", "report exceeds 10 MiB")
    required = {"standard", "agent", "run", "source", "status", "errors", "errors_total", "error_counts",
                "findings", "findings_total"}
    if not _keys(p, report, "$", required, {"extensions"}):
        return p.items
    if report["standard"] != AGENT_STANDARD:
        p.add("$.standard", "unsupported standard")
    agent_name = ""
    if _keys(p, report["agent"], "$.agent", {"name", "version"}):
        if _is(report["agent"]["name"], AGENT_NAME):
            agent_name = report["agent"]["name"]
        else:
            p.add("$.agent.name", "invalid agent name")
        version = report["agent"]["version"]
        if not (_is(version, PRINTABLE) and len(version) <= 32):
            p.add("$.agent.version", "must be 1-32 printable ASCII characters")
    if _keys(p, report["run"], "$.run", {"id", "started_at", "finished_at"}):
        if not _is(report["run"]["id"], UUID4):
            p.add("$.run.id", "must be a lowercase UUID v4")
        a, b = _ts(p, report["run"]["started_at"], "$.run.started_at"), _ts(p, report["run"]["finished_at"], "$.run.finished_at")
        if a and b and b < a:
            p.add("$.run.finished_at", "earlier than started_at")
    if _keys(p, report["source"], "$.source", {"type", "description", "scope"}):
        src = report["source"]
        if not _is(src["type"], TOKEN):
            p.add("$.source.type", "invalid token")
        _text(p, src["description"], "$.source.description", 500)
        if isinstance(src["description"], str) and ABSOLUTE_PATH.search(src["description"]):
            p.add("$.source.description", "must not contain an absolute filesystem path")
        if not isinstance(src["scope"], list) or len(src["scope"]) > 100:
            p.add("$.source.scope", "must be an array of at most 100 items")
        else:
            for i, item in enumerate(src["scope"]):
                if _keys(p, item, f"$.source.scope[{i}]", {"kind", "id"}, {"count"}):
                    if not (_is(item["kind"], TOKEN) and _is(item["id"], TOKEN)):
                        p.add(f"$.source.scope[{i}]", "invalid kind or id")
                    if "count" in item and not _int_ok(item["count"]):
                        p.add(f"$.source.scope[{i}].count", "must be an integer >= 0")
    if "extensions" in report and not isinstance(report["extensions"], dict):
        p.add("$.extensions", "must be an object")

    status = report["status"]
    if status not in ("ok", "partial", "error"):
        p.add("$.status", "invalid status")
    counts = _validate_errors(p, report)
    total = report["errors_total"] if _int_ok(report["errors_total"]) else None
    if total is not None and status in ("ok", "partial", "error"):
        if (status == "ok") != (total == 0):
            p.add("$.status", "status inconsistent with errors_total")
    if "report-too-large" in counts and status != "error":
        p.add("$.status", "report-too-large requires status error")
    if status == "ok" and any(c in counts for c in RESERVED):
        p.add("$.status", "truncation requires status partial or error")

    findings = report["findings"]
    if not isinstance(findings, list) or len(findings) > 1000:
        p.add("$.findings", "must be an array of at most 1000 items")
        findings = []
    ids = []
    for i, f in enumerate(findings):
        fid = _validate_finding(p, f, f"$.findings[{i}]", agent_name, counts)
        if fid:
            ids.append(fid)
    if len(ids) != len(set(ids)):
        p.add("$.findings", "duplicate finding_id")
    if _int_ok(report["findings_total"]):
        dropped = report["findings_total"] != len(findings)
        if report["findings_total"] < len(findings) or dropped != ("findings-truncated" in counts):
            p.add("$.findings_total", "inconsistent with findings and findings-truncated")
        if dropped and all(isinstance(f, dict) for f in findings):
            if findings != sorted(findings, key=lambda f: (RANK.get(f.get("severity"), 9) if isinstance(f.get("severity"), str) else 9, str(f.get("finding_id")))):
                p.add("$.findings", "truncated findings not in ranking order")
    else:
        p.add("$.findings_total", "must be an integer >= 0")
    if findings and "details-omitted-for-size" in counts and not any(
            isinstance(f, dict) and f.get("evidence_details_omitted") is True for f in findings):
        p.add("$.errors", "details-omitted-for-size without omitted details")
    if findings and "evidence-truncated-for-size" in counts and not any(
            isinstance(f, dict) and isinstance(f.get("evidence"), list) and _int_ok(f.get("evidence_total"))
            and len(f["evidence"]) < min(500, f["evidence_total"]) for f in findings):
        p.add("$.errors", "evidence-truncated-for-size without cut evidence")
    return p.items


def _validate_errors(p: Problems, report: dict) -> dict:
    errors, total, counts = report["errors"], report["errors_total"], report["error_counts"]
    if not _int_ok(total):
        p.add("$.errors_total", "must be an integer >= 0")
        total = None
    if not isinstance(errors, list) or len(errors) > 100:
        p.add("$.errors", "must be an array of at most 100 items")
        errors = []
    well_formed = True
    for i, e in enumerate(errors):
        path = f"$.errors[{i}]"
        if not _keys(p, e, path, {"code", "message"}, {"ref"}):
            well_formed = False
            continue
        if not _is(e["code"], CODE) or e["code"] == "other-codes":
            p.add(f"{path}.code", "invalid or reserved code")
            well_formed = False
        _text(p, e["message"], f"{path}.message", 500)
        if not isinstance(e["message"], str):
            well_formed = False
        if "ref" in e and not _ref_ok(e["ref"]):
            p.add(f"{path}.ref", "invalid ref")
            well_formed = False
    if total is not None and len(errors) != min(100, total):
        p.add("$.errors", "must list min(100, errors_total) errors")
    if well_formed and errors != _ordered(errors):
        p.add("$.errors", "errors not in the required order")
    if not isinstance(counts, dict) or len(counts) > 100:
        p.add("$.error_counts", "must be an object with at most 100 keys")
        return {}
    for code, n in counts.items():
        if not (code == "other-codes" or _is(code, CODE)) or not _int_ok(n, 1):
            p.add("$.error_counts", "invalid code or count")
            return {}
    if "other-codes" in counts and len(counts) != 100:
        p.add("$.error_counts", "other-codes only with 99 retained codes")
    if total is not None and sum(counts.values()) != total:
        p.add("$.error_counts", "counts do not add up to errors_total")
    for e in errors:
        if isinstance(e, dict) and isinstance(e.get("code"), str) and e["code"] not in counts \
                and "other-codes" not in counts:
            p.add("$.error_counts", "listed error code not counted")
            break
    for code in RESERVED:
        if code in counts and not any(isinstance(e, dict) and e.get("code") == code for e in errors):
            p.add("$.errors", "reserved code counted but not listed")
    return counts


def _validate_finding(p: Problems, f, path: str, agent: str, counts: dict) -> str | None:
    required = {"finding_id", "created_at", "rule_id", "severity", "observation", "assessment", "recommendation",
                "limitations", "evidence", "evidence_total", "evidence_refs_digest"}
    if not _keys(p, f, path, required, {"evidence_details_omitted", "data_warnings", "data_warnings_total"}):
        return None
    _ts(p, f["created_at"], f"{path}.created_at")
    rule_ok = _is(f["rule_id"], CODE)
    if not rule_ok:
        p.add(f"{path}.rule_id", "invalid rule id")
    if not isinstance(f["severity"], str) or f["severity"] not in RANK:
        p.add(f"{path}.severity", "must be low, medium or high")
    for field in ("observation", "assessment", "recommendation", "limitations"):
        _text(p, f[field], f"{path}.{field}", 2000)
    evidence = f["evidence"] if isinstance(f["evidence"], list) else []
    if not 1 <= len(evidence) <= 500:
        p.add(f"{path}.evidence", "must have 1-500 items")
    refs, details = [], False
    for j, item in enumerate(evidence):
        if not _keys(p, item, f"{path}.evidence[{j}]", {"ref"}, {"timestamp", "details"}):
            continue
        if _ref_ok(item["ref"]):
            refs.append(item["ref"])
        else:
            p.add(f"{path}.evidence[{j}].ref", "invalid ref")
        if "timestamp" in item:
            _ts(p, item["timestamp"], f"{path}.evidence[{j}].timestamp")
        if "details" in item:
            details = True
            if not isinstance(item["details"], dict):
                p.add(f"{path}.evidence[{j}].details", "must be an object")
    if len(set(refs)) != len(refs):
        p.add(f"{path}.evidence", "duplicate refs")
    total, digest = f["evidence_total"], f["evidence_refs_digest"]
    if not _int_ok(total, 1) or total < len(evidence):
        p.add(f"{path}.evidence_total", "invalid evidence_total")
    elif total > len(evidence):
        if refs != canonical_refs(refs):
            p.add(f"{path}.evidence", "truncated evidence not in canonical order")
        if not (len(evidence) == min(500, total) or
                (len(evidence) == min(100, total) and "evidence-truncated-for-size" in counts)):
            p.add(f"{path}.evidence", "evidence truncated to an invalid length")
    digest_ok = _is(digest, HEX64)
    if not digest_ok:
        p.add(f"{path}.evidence_refs_digest", "must be 64 lowercase hex characters")
    elif total == len(evidence) == len(refs) and refs_digest(refs) != digest:
        p.add(f"{path}.evidence_refs_digest", "does not match the evidence")
    fid = f["finding_id"]
    if rule_ok and digest_ok and agent and fid != finding_id(agent, f["rule_id"], digest):
        p.add(f"{path}.finding_id", "does not match agent, rule and digest")
    if "evidence_details_omitted" in f and (f["evidence_details_omitted"] is not True or details
                                            or "details-omitted-for-size" not in counts):
        p.add(f"{path}.evidence_details_omitted", "inconsistent")
    if ("data_warnings" in f) != ("data_warnings_total" in f):
        p.add(path, "data_warnings and data_warnings_total must appear together")
    elif "data_warnings" in f:
        warnings = f["data_warnings"]
        if not isinstance(warnings, list) or len(warnings) > 50 or not _int_ok(f["data_warnings_total"], 1) \
                or len(warnings) != min(50, f["data_warnings_total"]):
            p.add(f"{path}.data_warnings", "invalid data warnings or total")
        else:
            for k, w in enumerate(warnings):
                wp = f"{path}.data_warnings[{k}]"
                if _keys(p, w, wp, {"field", "refs", "refs_total", "warning"}):
                    if not _is(w["field"], FIELD):
                        p.add(f"{wp}.field", "invalid field name")
                    if not isinstance(w["refs"], list) or len(w["refs"]) > 100 or not all(_ref_ok(r) for r in w["refs"]) \
                            or not _int_ok(w["refs_total"], 1) or len(w["refs"]) != min(100, w["refs_total"]):
                        p.add(f"{wp}.refs", "invalid refs or refs_total")
                    _text(p, w["warning"], f"{wp}.warning", 500)
    return fid if isinstance(fid, str) else None


# --- describe ---------------------------------------------------------------------------------


def validate_describe(data: Any, expected_name: str) -> list[str]:
    p = Problems()
    if not _keys(p, data, "describe", {"standard", "name", "version", "responsibility", "personal_data"}):
        return p.items
    if data["standard"] != AGENT_STANDARD:
        p.add("describe.standard", "unsupported standard")
    if data["name"] != expected_name:
        p.add("describe.name", "does not match expected_name")
    if not (_is(data["version"], PRINTABLE) and len(data["version"]) <= 32):
        p.add("describe.version", "invalid version")
    _text(p, data["responsibility"], "describe.responsibility", 200)
    if not isinstance(data["personal_data"], list) or not all(_is(x, TOKEN) for x in data["personal_data"]):
        p.add("describe.personal_data", "must be a list of tokens")
    return p.items
