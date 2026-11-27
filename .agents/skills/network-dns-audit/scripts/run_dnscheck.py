#!/usr/bin/env python3
"""
Zero-dependency helper runner for the `network-dns-audit` Agent Skill.

Capabilities:
1. `--check-env`: Inspect local availability of `dnscheck` and native network
   diagnostic utilities, returning a clean JSON summary for the agent.
2. Any other arguments: Automatically locate `dnscheck` (env var, repo checkout,
   installed package, or PATH) and forward arguments transparently.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


NATIVE_TOOLS = (
    "dig",
    "nslookup",
    "curl",
    "openssl",
    "ping",
    "traceroute",
    "mtr",
    "nc",
    "scutil",
    "networksetup",
    "lsof",
    "ip",
    "ss",
    "resolvectl",
    "surge-cli",
)


def find_dnscheck_command() -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Locate a runnable `dnscheck` invocation in priority order:
    1. `$DNSCHECK_HOME/dnscheck.py`
    2. Repo-local `dnscheck.py` (relative to this script or CWD ancestors)
    3. `dnscheck` executable on PATH
    4. `python3 -m dnscheck` importable in current Python environment
    """
    env_home = os.environ.get("DNSCHECK_HOME")
    if env_home:
        candidate = Path(env_home).expanduser().resolve() / "dnscheck.py"
        if candidate.is_file():
            return [sys.executable, str(candidate)], f"env:DNSCHECK_HOME ({candidate})"

    # Check ancestors of this script (e.g., <repo>/.agents/skills/network-dns-audit/scripts/run_dnscheck.py)
    script_path = Path(__file__).resolve()
    search_roots = list(script_path.parents) + [Path.cwd().resolve(), *Path.cwd().resolve().parents]
    seen = set()
    for root in search_roots:
        if root in seen:
            continue
        seen.add(root)
        candidate = root / "dnscheck.py"
        pkg_dir = root / "dnscheck"
        if candidate.is_file() and pkg_dir.is_dir():
            return [sys.executable, str(candidate)], f"repo ({candidate})"

    which_bin = shutil.which("dnscheck")
    if which_bin:
        return [which_bin], f"PATH ({which_bin})"

    # Check if dnscheck is importable as a module
    probe = subprocess.run(
        [sys.executable, "-c", "import dnscheck; print(dnscheck.__version__)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode == 0:
        ver = probe.stdout.strip() or "unknown"
        return [sys.executable, "-m", "dnscheck"], f"python-module (v{ver})"

    return None, None


def find_surge_cli() -> Optional[str]:
    """Detect Surge for Mac CLI in standard paths or PATH."""
    for cand in (
        "/Applications/Surge.app/Contents/Applications/surge-cli",
        "/usr/local/bin/surge-cli",
        "/opt/homebrew/bin/surge-cli",
    ):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("surge-cli")


def check_environment() -> dict:
    """Return a JSON-serializable summary of available diagnostic tools."""
    cmd, source = find_dnscheck_command()
    tools = {name: shutil.which(name) for name in NATIVE_TOOLS}
    if not tools.get("surge-cli"):
        tools["surge-cli"] = find_surge_cli()

    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "python_version": platform.python_version(),
        "dnscheck_available": cmd is not None,
        "dnscheck_command": cmd,
        "dnscheck_source": source,
        "available_native_tools": {k: v for k, v in tools.items() if v},
        "missing_native_tools": [k for k, v in tools.items() if not v],
        "hints": (
            [
                "dnscheck is ready. Prefer running subcommands with `--json` for structured analysis.",
                "DNS leak, OAST, STUN, and split-routing checks require real host network access (not an offline sandbox).",
            ]
            if cmd
            else [
                "dnscheck was not found in the current repo, PATH, or Python environment.",
                "Install it globally with `pip3 install --no-deps -e .` from the DNSGuard repository, or set DNSCHECK_HOME.",
                "You can still fall back to native OS commands listed in references/general-network-and-fallback.md.",
            ]
        ),
    }


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args == ["--help"] or args == ["-h"]:
        print(
            "Usage:\n"
            "  python3 run_dnscheck.py --check-env\n"
            "  python3 run_dnscheck.py <dnscheck-subcommand> [args...]\n\n"
            "Examples:\n"
            "  python3 run_dnscheck.py env --json\n"
            "  python3 run_dnscheck.py leak --json\n"
            "  python3 run_dnscheck.py audit --json\n"
            "  python3 run_dnscheck.py claude --json\n"
            "  python3 run_dnscheck.py all --json\n"
        )
        return 0

    if args[0] == "--check-env":
        print(json.dumps(check_environment(), ensure_ascii=False, indent=2))
        return 0

    cmd, _ = find_dnscheck_command()
    if not cmd:
        sys.stderr.write(
            "[network-dns-audit] Could not locate `dnscheck`.\n"
            "Tip: Run `pip3 install --no-deps -e .` inside the dns-leak-guard repo, "
            "set `DNSCHECK_HOME=/path/to/dns-leak-guard`, or fall back to native commands "
            "in `references/general-network-and-fallback.md`.\n"
        )
        return 127

    completed = subprocess.run([*cmd, *args], check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
