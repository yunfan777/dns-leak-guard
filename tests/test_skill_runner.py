"""Unit tests for the network-dns-audit Agent Skill helper runner and files."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".agents" / "skills" / "network-dns-audit"
RUNNER_SCRIPT = SKILL_DIR / "scripts" / "run_dnscheck.py"
PROMPTS_DIR = REPO_ROOT / "prompts"


class TestSkillAndPrompts(unittest.TestCase):
    def test_skill_files_exist_with_valid_frontmatter(self) -> None:
        skill_md = SKILL_DIR / "SKILL.md"
        self.assertTrue(skill_md.is_file(), "SKILL.md must exist")
        text = skill_md.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"), "SKILL.md must start with YAML frontmatter")
        self.assertIn("name: network-dns-audit", text)
        self.assertIn("description:", text)

        for rel in (
            "references/remediation.md",
            "references/remediation_zh.md",
            "references/general-network-and-fallback.md",
            "scripts/run_dnscheck.py",
        ):
            self.assertTrue((SKILL_DIR / rel).is_file(), f"Missing skill asset: {rel}")

    def test_prompt_files_exist(self) -> None:
        for name in (
            "README.md",
            "README_CN.md",
            "network-dns-audit.md",
            "network-dns-audit_zh.md",
        ):
            self.assertTrue((PROMPTS_DIR / name).is_file(), f"Missing prompt asset: {name}")

    def test_runner_check_env_discovers_repo_dnscheck(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(RUNNER_SCRIPT), "--check-env"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["dnscheck_available"])
        self.assertIsInstance(data["dnscheck_command"], list)
        self.assertTrue(len(data["dnscheck_command"]) >= 1)
        self.assertIn("available_native_tools", data)

    def test_runner_forwards_version_flag(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(RUNNER_SCRIPT), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("DNSGuard", proc.stdout)


if __name__ == "__main__":
    unittest.main()
