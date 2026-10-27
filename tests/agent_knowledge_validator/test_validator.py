"""Black-box contract tests for validate-agent-knowledge.py."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = SOURCE_ROOT / "scripts" / "validate-agent-knowledge.py"
AGENT_TEXT = """# Repository guidance

## Continuous Agent & Skills Maintenance

Keep operational guidance accurate and reusable.

See [the readme](README.md).
"""
SKILL_TEXT = """---
name: example
description: Guidance for the example subsystem.
---
# Example skill

## Maintenance & Continuous Learning

Keep the procedure current.
"""


class ValidatorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        shutil.copy2(VALIDATOR, self.repo / "scripts" / VALIDATOR.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Validator Test")
        self.git("config", "user.email", "validator@example.invalid")
        self.write("AGENTS.md", AGENT_TEXT)
        self.write("README.md", "Repository fixture.\n")
        self.write("src/example.py", "VALUE = 1\n")
        self.write(".agents/skills/example/SKILL.md", SKILL_TEXT)
        self.commit("baseline")
        self.base = self.git("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str, check: bool = True) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        if check and result.returncode:
            self.fail(result.stderr)
        return result.stdout

    def write(self, relative: str, content: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_validator(
        self, *arguments: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.repo / "scripts" / VALIDATOR.name), *arguments],
            cwd=cwd or self.repo,
            text=True,
            capture_output=True,
            check=False,
        )

    def update_agent(self) -> None:
        path = self.repo / "AGENTS.md"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\nWhen parser boundaries change, update examples and rerun compatibility review.\n",
            encoding="utf-8",
        )

    def test_clean_worktree_passes(self) -> None:
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Status: PASS", result.stdout)
        self.assertIn("Errors: 0", result.stdout)

    def test_code_change_without_knowledge_update_fails(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] AK001", result.stdout)

    def test_code_change_with_agents_update_passes_with_review_warning(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        self.update_agent()
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[PASS] AK001", result.stdout)
        self.assertIn("[WARN] AK004", result.stdout)

    def test_code_change_with_skill_update_passes(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        skill = self.repo / ".agents/skills/example/SKILL.md"
        skill.write_text(
            skill.read_text(encoding="utf-8")
            + "\nWhen this parser changes, retain compatibility examples in this skill.\n",
            encoding="utf-8",
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cosmetic_knowledge_change_fails_ak001_and_ak004(self) -> None:
        path = self.repo / "AGENTS.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "operational guidance", "operational  guidance"
            ),
            encoding="utf-8",
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] AK004", result.stdout)

    def test_malformed_skill_fails_ak002(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        self.update_agent()
        self.write(
            ".agents/skills/example/SKILL.md",
            "---\nname: example\n---\n# Broken\n",
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] AK002", result.stdout)

    def test_broken_internal_reference_fails_ak003(self) -> None:
        self.update_agent()
        self.write(
            "AGENTS.md",
            (self.repo / "AGENTS.md").read_text(encoding="utf-8")
            + "\nSee [missing](docs/missing.md).\n",
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] AK003", result.stdout)

    def test_untracked_project_file_is_discovered(self) -> None:
        self.write("src/new.py", "VALUE = 3\n")
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/new.py", result.stdout)

    def test_path_with_spaces_and_special_characters_is_discovered(self) -> None:
        path = "src/new file [draft] (1).py"
        self.write(path, "VALUE = 3\n")
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn(path, result.stdout)

    def test_renamed_project_file_is_discovered(self) -> None:
        self.git("mv", "src/example.py", "src/renamed.py")
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] AK001", result.stdout)

    def test_deleted_project_file_is_discovered(self) -> None:
        (self.repo / "src/example.py").unlink()
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("src/example.py", result.stdout)

    def test_staged_and_unstaged_changes_are_combined(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        self.git("add", "src/example.py")
        self.update_agent()
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_valid_range_uses_base_and_head(self) -> None:
        self.write("src/example.py", "VALUE = 2\n")
        self.update_agent()
        self.commit("code and knowledge")
        head = self.git("rev-parse", "HEAD").strip()
        result = self.run_validator(
            "--scope", "range", "--base", self.base, "--head", head
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_revision_returns_execution_error(self) -> None:
        result = self.run_validator(
            "--scope", "range", "--base", "missing", "--head", "HEAD"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("[FAIL] AK005", result.stdout)

    def test_invalid_configuration_returns_execution_error(self) -> None:
        self.write(
            ".agent-knowledge-validator.toml",
            '[validator]\ncontract_version = "9.9.9"\n',
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("[FAIL] AK005", result.stdout)

    def test_incompatible_cli_arguments_return_usage_error(self) -> None:
        result = self.run_validator("--scope", "range", "--base", self.base)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires both --base and --head", result.stderr)

    def test_help_uses_standard_argument_documentation(self) -> None:
        result = self.run_validator("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--scope {worktree,range}", result.stdout)
        self.assertIn("--format {text,json}", result.stdout)

    def test_outside_git_repository_returns_execution_error(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        result = self.run_validator("--scope", "worktree", cwd=outside)
        self.assertEqual(result.returncode, 2)
        self.assertIn("[FAIL] AK005", result.stdout)

    def test_json_output_is_machine_readable(self) -> None:
        result = self.run_validator("--scope", "worktree", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["contract_version"], "1.0.0")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["checks"]), 7)

    def test_explicit_exclusion_does_not_trigger_ak001(self) -> None:
        self.write(
            ".agent-knowledge-validator.toml",
            '[validator]\ncontract_version = "1.0.0"\nexclude_paths = ["generated/**"]\n',
        )
        self.commit("configure generated path exclusion")
        self.write("generated/output.txt", "Generated output.\n")
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_repeated_validation_is_idempotent(self) -> None:
        first = self.run_validator("--scope", "worktree", "--format", "json")
        second = self.run_validator("--scope", "worktree", "--format", "json")
        self.assertEqual(first.returncode, second.returncode)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)

    def test_conflicting_directives_are_reported(self) -> None:
        path = self.repo / "AGENTS.md"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\nOperators must retain exclusive control of validation results.\n"
            + "Operators must not retain exclusive control of validation results.\n",
            encoding="utf-8",
        )
        result = self.run_validator("--scope", "worktree")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[WARN] AK006", result.stdout)


if __name__ == "__main__":
    unittest.main()
