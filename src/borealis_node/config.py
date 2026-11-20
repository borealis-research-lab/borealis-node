"""node.json: TRUSTED ADMINISTRATIVE CONFIGURATION.

Whoever can edit this file can make Borealis Node run any program. Protect it like any
other administrator-owned configuration. The Node runs only what is listed here: an absolute
path to an existing executable plus an argument list. No shell, no PATH lookup.

    {"agents": [
      {"config_name": "nyyrikki", "expected_name": "nyyrikki",
       "executable": "C:/borealis/security-event-analysis/.venv/Scripts/nyyrikki.exe",
       "args": ["scan", "C:/borealis/exports/security.xml"], "timeout_s": 300}
    ]}
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from borealis_node.validate import InvalidJson, strict_loads

MAX_AGENTS = 32
RE_CONFIG_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
RE_AGENT_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")


class ConfigError(ValueError):
    pass


@dataclass
class AgentConfig:
    config_name: str
    expected_name: str
    executable: str
    args: list[str]
    timeout_s: float
    cwd: str | None = None


def load(path: str | Path) -> list[AgentConfig]:
    try:
        data = strict_loads(Path(path).read_bytes())
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc.strerror or exc}") from None
    except InvalidJson as exc:
        raise ConfigError(f"config is not valid JSON: {exc}") from None
    if not isinstance(data, dict) or set(data) != {"agents"} or not isinstance(data["agents"], list):
        raise ConfigError("config must be an object with exactly one field, 'agents' (a list)")
    agents = data["agents"]
    if not 1 <= len(agents) <= MAX_AGENTS:
        raise ConfigError(f"configure 1-{MAX_AGENTS} agents")
    result, names = [], set()
    allowed = {"config_name", "expected_name", "executable", "args", "timeout_s", "cwd"}
    for i, item in enumerate(agents):
        where = f"agents[{i}]"
        if not isinstance(item, dict) or not {"config_name", "expected_name", "executable", "args", "timeout_s"} <= set(item) \
                or set(item) - allowed:
            raise ConfigError(f"{where} needs config_name, expected_name, executable, args, timeout_s (and optional cwd)")
        name = item["config_name"]
        if not isinstance(name, str) or not RE_CONFIG_NAME.fullmatch(name):
            raise ConfigError(f"{where}.config_name must match [a-z][a-z0-9-]{{0,31}} (it is used as a file name)")
        if name in names:
            raise ConfigError(f"{where}.config_name {name!r} is not unique")
        names.add(name)
        if not isinstance(item["expected_name"], str) or not RE_AGENT_NAME.fullmatch(item["expected_name"]):
            raise ConfigError(f"{where}.expected_name is not a valid agent name")
        exe = item["executable"]
        if not isinstance(exe, str) or not os.path.isabs(exe):
            raise ConfigError(f"{where}.executable must be an absolute path (no PATH lookup)")
        args = item["args"]
        if not isinstance(args, list) or not all(isinstance(a, str) and "\x00" not in a for a in args):
            raise ConfigError(f"{where}.args must be a list of strings")
        timeout = item["timeout_s"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 86400:
            raise ConfigError(f"{where}.timeout_s must be an integer between 1 and 86400")
        cwd = item.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isdir(cwd)):
            raise ConfigError(f"{where}.cwd must be an absolute path to an existing directory")
        result.append(AgentConfig(name, item["expected_name"], exe, list(args), float(timeout), cwd))
    return result


def example() -> str:
    return json.dumps({"agents": [{"config_name": "nyyrikki", "expected_name": "nyyrikki",
                                   "executable": "/absolute/path/to/nyyrikki", "args": ["scan", "/path/export.xml"],
                                   "timeout_s": 300}]}, indent=2)
