#!/usr/bin/env python3
"""Validate the shared Agent Knowledge Validation contract."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

CONTRACT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
CONFIG_NAME = ".agent-knowledge-validator.toml"
RULE_NAMES = {
    "AK001": "Agent knowledge synchronization",
    "AK002": "Agent and skill structure",
    "AK003": "Internal references",
    "AK004": "Knowledge update relevance",
    "AK005": "Validator configuration and execution",
    "AK006": "Duplicate or conflicting instructions",
}
INSTRUCTION_NAMES = {
    "AGENTS.md",
    "AGENT.md",
    "SKILL.md",
    "CLAUDE.md",
    "GEMINI.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
}
INSTRUCTION_SUFFIXES = (".agent.md", ".instructions.md", ".mdc")
INFRASTRUCTURE_PATTERNS = (
    "scripts/validate-agent-knowledge.py",
    "**/scripts/validate-agent-knowledge.py",
    "tests/agent_knowledge_validator/**",
    "**/tests/agent_knowledge_validator/**",
    ".github/workflows/agent-knowledge-validation.yml",
    "**/agent-knowledge-validation.yml",
    "**/agent-knowledge-validation.yaml",
)
DEFAULT_EXCLUDED_PATHS = ("__pycache__/**", "**/__pycache__/**")
METADATA_LINE = re.compile(
    r"(?i)^(?:updated?|generated|last[ -]updated|date|updated_at)\s*[:=]"
)
LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
CONFLICT_PATTERN = re.compile(
    r"(?i)^\s*(?P<prefix>.*?)\b"
    r"(?P<modal>must not|mustn't|must|should not|should|do not|don't|never|always)"
    r"\b\s+(?P<action>[^.!?]{12,})[.!?]?\s*$"
)


@dataclass(frozen=True)
class CheckResult:
    rule_id: str
    status: str
    message: str
    files: tuple[str, ...] = ()
    remediation: str | None = None


@dataclass(frozen=True)
class Change:
    status: str
    path: str


class ValidationError(Exception):
    """A repository, Git, or configuration error that prevents validation."""


def run_git(root: Path, *args: str, check: bool = True) -> str:
    """Run Git without a shell and return its UTF-8 output."""
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or f"git {' '.join(args)} failed"
        raise ValidationError(detail)
    return result.stdout


def find_repository_root(cwd: Path) -> Path:
    """Return the current worktree root; do not infer it from this script's path."""
    output = run_git(cwd, "rev-parse", "--show-toplevel")
    return Path(output.strip()).resolve()


def parse_config(root: Path) -> dict[str, Any]:
    """Load the optional, explicitly scoped repository configuration."""
    path = root / CONFIG_NAME
    if not path.exists():
        return {
            "exclude_paths": [],
            "instruction_globs": [],
            "required_headings": {},
            "required_phrases": {},
            "strict_text": {},
            "skill_reference_prefixes": [],
            "inline_path_checks": False,
            "minimum_changed_lines": 1,
        }
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"{CONFIG_NAME}: {exc}") from exc
    if set(value) - {"validator"}:
        raise ValidationError(f"{CONFIG_NAME}: only the [validator] table is supported")
    settings = value.get("validator", {})
    if not isinstance(settings, dict):
        raise ValidationError(f"{CONFIG_NAME}: [validator] must be a table")
    allowed = {
        "contract_version",
        "exclude_paths",
        "instruction_globs",
        "required_headings",
        "required_phrases",
        "strict_text",
        "skill_reference_prefixes",
        "inline_path_checks",
        "minimum_changed_lines",
    }
    unknown = set(settings) - allowed
    if unknown:
        raise ValidationError(
            f"{CONFIG_NAME}: unknown setting(s): {', '.join(sorted(unknown))}"
        )
    version = settings.get("contract_version", CONTRACT_VERSION)
    if version != CONTRACT_VERSION:
        raise ValidationError(
            f"{CONFIG_NAME}: contract_version must be {CONTRACT_VERSION!r}"
        )
    parsed: dict[str, Any] = {}
    for key in ("exclude_paths", "instruction_globs"):
        items = settings.get(key, [])
        if not isinstance(items, list) or not all(
            isinstance(item, str) and item.strip() for item in items
        ):
            raise ValidationError(
                f"{CONFIG_NAME}: {key} must be an array of non-empty strings"
            )
        for item in items:
            candidate = PurePosixPath(item)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValidationError(
                    f"{CONFIG_NAME}: {key} entries must be repository-relative: {item}"
                )
        parsed[key] = items
    for key in ("required_headings", "required_phrases"):
        mapping = settings.get(key, {})
        if not isinstance(mapping, dict):
            raise ValidationError(
                f"{CONFIG_NAME}: {key} must be a table of paths to arrays"
            )
        validated: dict[str, list[str]] = {}
        for path, values in mapping.items():
            candidate = PurePosixPath(path)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValidationError(
                    f"{CONFIG_NAME}: {key} paths must be repository-relative: {path}"
                )
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value.strip() for value in values
            ):
                raise ValidationError(
                    f"{CONFIG_NAME}: {key}.{path} must be an array of non-empty strings"
                )
            validated[path] = values
        parsed[key] = validated
    known_instruction_paths = set(
        discover_instruction_files(root, parsed["instruction_globs"])
    )
    for key in ("required_headings", "required_phrases"):
        unknown_paths = set(parsed[key]) - known_instruction_paths
        if unknown_paths:
            raise ValidationError(
                f"{CONFIG_NAME}: {key} references unknown instruction path(s): "
                + ", ".join(sorted(unknown_paths))
            )
    strict_text = settings.get("strict_text", {})
    if not isinstance(strict_text, dict):
        raise ValidationError(f"{CONFIG_NAME}: strict_text must be a table")
    allowed_text_rules = {
        "ascii_only",
        "lf_only",
        "final_newline",
        "no_trailing_whitespace",
        "no_nul",
    }
    parsed_strict: dict[str, list[str]] = {}
    for pattern, rules in strict_text.items():
        candidate = PurePosixPath(pattern)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValidationError(
                f"{CONFIG_NAME}: invalid strict_text pattern: {pattern}"
            )
        if not isinstance(rules, list) or not all(
            isinstance(rule, str) and rule in allowed_text_rules for rule in rules
        ):
            raise ValidationError(
                f"{CONFIG_NAME}: strict_text.{pattern} has an unknown rule"
            )
        parsed_strict[pattern] = rules
    parsed["strict_text"] = parsed_strict
    prefixes = settings.get("skill_reference_prefixes", [])
    if not isinstance(prefixes, list) or not all(
        isinstance(prefix, str) and prefix for prefix in prefixes
    ):
        raise ValidationError(
            f"{CONFIG_NAME}: skill_reference_prefixes must be an array"
        )
    parsed["skill_reference_prefixes"] = prefixes
    inline_checks = settings.get("inline_path_checks", False)
    if not isinstance(inline_checks, bool):
        raise ValidationError(f"{CONFIG_NAME}: inline_path_checks must be a boolean")
    parsed["inline_path_checks"] = inline_checks
    minimum_lines = settings.get("minimum_changed_lines", 1)
    if not isinstance(minimum_lines, int) or not 1 <= minimum_lines <= 1000:
        raise ValidationError(
            f"{CONFIG_NAME}: minimum_changed_lines must be an integer from 1 to 1000"
        )
    parsed["minimum_changed_lines"] = minimum_lines
    return parsed


def is_instruction(path: str, extra_globs: Sequence[str] = ()) -> bool:
    """Classify supported agent, skill, and tool instruction documents."""
    posix = PurePosixPath(path)
    if posix.name in INSTRUCTION_NAMES or posix.name.endswith(INSTRUCTION_SUFFIXES):
        return True
    if ".cursor" in posix.parts and posix.parent.name == "rules":
        return True
    if ".windsurf" in posix.parts and posix.parent.name == "rules":
        return True
    if ".continue" in posix.parts and posix.parent.name == "rules":
        return True
    if path == ".agents/skills/README.md":
        return True
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in extra_globs)


def is_excluded(path: str, patterns: Sequence[str]) -> bool:
    """Match an explicit repository-relative exclusion."""
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def parse_name_status(raw: str) -> list[Change]:
    """Parse `git diff --name-status -z --no-renames` output safely."""
    fields = raw.split("\0")
    changes: list[Change] = []
    index = 0
    while index + 1 < len(fields):
        status, path = fields[index], fields[index + 1]
        index += 2
        if status and path:
            changes.append(Change(status[0], path))
    return changes


def discover_changes(
    root: Path, scope: str, base: str | None, head: str | None
) -> list[Change]:
    """Find tracked, untracked, staged, unstaged, renamed, and deleted paths."""
    if scope == "worktree":
        tracked = run_git(root, "diff", "--name-status", "-z", "--no-renames", "HEAD")
        changes = parse_name_status(tracked)
        untracked = run_git(root, "ls-files", "--others", "--exclude-standard", "-z")
        changes.extend(Change("A", path) for path in untracked.split("\0") if path)
        return _deduplicate_changes(changes)
    assert base is not None and head is not None
    base_commit = resolve_commit(root, base)
    head_commit = resolve_commit(root, head)
    merge_base = run_git(root, "merge-base", base_commit, head_commit).strip()
    raw = run_git(
        root,
        "diff",
        "--name-status",
        "-z",
        "--no-renames",
        merge_base,
        head_commit,
    )
    return _deduplicate_changes(parse_name_status(raw))


def _deduplicate_changes(changes: Sequence[Change]) -> list[Change]:
    by_path: dict[str, Change] = {}
    for change in changes:
        by_path[change.path] = change
    return [by_path[path] for path in sorted(by_path)]


def resolve_commit(root: Path, revision: str) -> str:
    """Resolve a Git revision to a commit or raise a configuration error."""
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValidationError(f"revision does not resolve to a commit: {revision}")
    return result.stdout.strip()


def changed_content(
    root: Path, scope: str, base: str | None, head: str | None, path: str
) -> tuple[list[str], list[str]]:
    """Return normalized added and removed content for one path."""
    if scope == "range":
        assert base is not None and head is not None
        base_commit = resolve_commit(root, base)
        head_commit = resolve_commit(root, head)
        merge_base = run_git(root, "merge-base", base_commit, head_commit).strip()
        diff = run_git(
            root,
            "diff",
            "--no-ext-diff",
            "--unified=0",
            merge_base,
            head_commit,
            "--",
            path,
        )
    else:
        diff = run_git(root, "diff", "--no-ext-diff", "--unified=0", "HEAD", "--", path)
    added: list[str] = []
    removed: list[str] = []
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            normalized = normalize_knowledge_line(line[1:])
            if normalized:
                added.append(normalized)
        elif line.startswith("-"):
            normalized = normalize_knowledge_line(line[1:])
            if normalized:
                removed.append(normalized)
    if (
        scope == "worktree"
        and not diff
        and path
        in {change.path for change in discover_changes(root, scope, base, head)}
    ):
        candidate = root / path
        if candidate.is_file() and not run_git(
            root, "ls-files", "--error-unmatch", "--", path, check=False
        ):
            try:
                added.extend(
                    item
                    for line in candidate.read_text(encoding="utf-8").splitlines()
                    if (item := normalize_knowledge_line(line))
                )
            except (OSError, UnicodeError):
                pass
    return added, removed


def normalize_knowledge_line(line: str) -> str:
    """Ignore whitespace, headings, comments, and metadata-only edits."""
    content = line.strip()
    if not content or content.startswith(("#", "<!--", "-->")):
        return ""
    if METADATA_LINE.match(content):
        return ""
    if re.fullmatch(r"[-*_`~>| ]+", content):
        return ""
    return re.sub(r"\s+", " ", content).strip()


def update_metrics(added: Sequence[str], removed: Sequence[str]) -> tuple[int, int]:
    """Count effective changed lines and characters after canceling formatting edits."""
    remaining_added = list(added)
    remaining_removed: list[str] = []
    for old in removed:
        try:
            remaining_added.remove(old)
        except ValueError:
            remaining_removed.append(old)
    changed = remaining_added + remaining_removed
    effective_chars = sum(len(re.sub(r"[^A-Za-z0-9]", "", line)) for line in changed)
    return len(changed), effective_chars


def substantive_update(
    added: Sequence[str], removed: Sequence[str], minimum_lines: int
) -> bool:
    """Reject whitespace-only edits and require meaningful content changes."""
    line_count, effective_chars = update_metrics(added, removed)
    return line_count >= minimum_lines and effective_chars >= 24


def discover_instruction_files(root: Path, extra_globs: Sequence[str]) -> list[str]:
    """Find recognized instructions without following symlinks."""
    found: list[str] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name != ".git" and not (Path(current) / name).is_symlink()
        )
        for filename in filenames:
            absolute = Path(current) / filename
            if absolute.is_symlink():
                continue
            relative = absolute.relative_to(root).as_posix()
            if is_instruction(relative, extra_globs):
                found.append(relative)
    return sorted(found)


def validate_structure(
    root: Path,
    paths: Sequence[str],
    required_headings: dict[str, list[str]],
    required_phrases: dict[str, list[str]],
) -> list[tuple[str, str]]:
    """Validate recognized instruction conventions using partial frontmatter checks."""
    errors: list[tuple[str, str]] = []
    for relative in paths:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append((relative, "cannot read UTF-8 instruction file"))
            continue
        if not text.strip():
            errors.append((relative, "instruction file is empty"))
            continue
        for heading in required_headings.get(relative, []):
            if not has_heading(text, heading):
                errors.append((relative, f"missing configured section: {heading}"))
        for phrase in required_phrases.get(relative, []):
            normalized_text = re.sub(r"\s+", " ", text)
            normalized_phrase = re.sub(r"\s+", " ", phrase)
            if normalized_phrase not in normalized_text:
                errors.append((relative, f"missing configured policy text: {phrase}"))
        name = PurePosixPath(relative).name
        if name == "AGENTS.md" and relative == "AGENTS.md":
            if not has_heading(text, "Continuous Agent & Skills Maintenance"):
                errors.append(
                    (relative, "missing Continuous Agent & Skills Maintenance section")
                )
        elif name == "SKILL.md":
            fields = parse_frontmatter_fields(text)
            if fields is None:
                errors.append(
                    (relative, "missing or malformed YAML frontmatter delimiters")
                )
            else:
                for key in ("name", "description"):
                    if not fields.get(key, "").strip():
                        errors.append(
                            (relative, f"frontmatter requires non-empty {key}")
                        )
                if (
                    fields.get("name")
                    and fields["name"].strip() != PurePosixPath(relative).parent.name
                ):
                    errors.append(
                        (relative, "frontmatter name must match the skill directory")
                    )
            if not has_heading(text, "Maintenance & Continuous Learning"):
                errors.append(
                    (relative, "missing Maintenance & Continuous Learning section")
                )
        elif name.endswith(".agent.md"):
            if text.startswith("---"):
                fields = parse_frontmatter_fields(text)
                if fields is None:
                    errors.append((relative, "malformed YAML frontmatter delimiters"))
                elif (
                    not fields.get("name", "").strip()
                    or not fields.get("description", "").strip()
                ):
                    errors.append(
                        (relative, "agent frontmatter requires name and description")
                    )
            if not has_heading(text, "Post-Change Knowledge Synchronization"):
                errors.append(
                    (relative, "missing Post-Change Knowledge Synchronization section")
                )
    return errors


def validate_extensions(
    root: Path,
    paths: Sequence[str],
    config: dict[str, Any],
    skill_names: set[str],
) -> list[tuple[str, str]]:
    """Run explicitly configured repository-specific checks under AKX001."""
    errors: list[tuple[str, str]] = []
    for relative in paths:
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for pattern, rules in config["strict_text"].items():
            if not fnmatch.fnmatchcase(relative, pattern):
                continue
            if "lf_only" in rules and "\r" in text:
                errors.append(
                    (relative, "configured text rule requires LF line endings")
                )
            if "final_newline" in rules and text and not text.endswith("\n"):
                errors.append(
                    (relative, "configured text rule requires a final newline")
                )
            if "no_trailing_whitespace" in rules and re.search(
                r"[\t ]+$", text, re.MULTILINE
            ):
                errors.append(
                    (relative, "configured text rule forbids trailing whitespace")
                )
            if "no_nul" in rules and "\x00" in text:
                errors.append((relative, "configured text rule forbids NUL bytes"))
            if "ascii_only" in rules and not text.isascii():
                errors.append((relative, "configured text rule requires ASCII text"))

    prefixes = config["skill_reference_prefixes"]
    if prefixes:
        for relative in paths:
            if not relative.endswith(".agent.md"):
                continue
            try:
                text = (root / relative).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            for reference in re.findall(r"`([^`]+)`", text):
                if (
                    any(reference.startswith(prefix) for prefix in prefixes)
                    and reference not in skill_names
                ):
                    errors.append((relative, f"references missing skill: {reference}"))

    if config["inline_path_checks"]:
        path_suffixes = {".md", ".pl", ".pm", ".t", ".8", ".ignore"}
        for relative in paths:
            try:
                text = (root / relative).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            for target in re.findall(r"`([^`]+)`", text):
                if target.startswith("/") or any(char.isspace() for char in target):
                    continue
                if Path(target).suffix not in path_suffixes and target not in {
                    "Makefile",
                    "LICENSE",
                }:
                    continue
                candidates = ((root / relative).parent / target, root / target)
                if not any(candidate.exists() for candidate in candidates):
                    errors.append(
                        (relative, f"inline repository path does not exist: {target}")
                    )
    return errors


def parse_frontmatter_fields(text: str) -> dict[str, str] | None:
    """Read simple top-level frontmatter fields; this is not a YAML parser."""
    match = re.match(r"\A---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.DOTALL)
    if not match:
        return None
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        field = re.match(r"^([A-Za-z0-9_-]+):\s*(.*?)\s*$", line)
        if field:
            fields[field.group(1)] = field.group(2).strip("\"'")
    return fields


def has_heading(text: str, heading: str) -> bool:
    return bool(re.search(rf"(?m)^##+\s+{re.escape(heading)}\s*$", text))


def validate_references(root: Path, paths: Sequence[str]) -> list[tuple[str, str]]:
    """Check relative Markdown links in recognized instruction files."""
    errors: list[tuple[str, str]] = []
    root_resolved = root.resolve()
    for relative in paths:
        file_path = root / relative
        try:
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for target in LINK_PATTERN.findall(text):
            destination = target.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(destination)
            if parsed.scheme or parsed.netloc:
                continue
            if not parsed.path:
                continue
            local_path = unquote(parsed.path)
            candidate = (
                (root / local_path.lstrip("/"))
                if local_path.startswith("/")
                else (file_path.parent / local_path)
            )
            resolved = candidate.resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                errors.append(
                    (relative, f"local reference escapes repository: {destination}")
                )
                continue
            if not resolved.exists():
                errors.append((relative, f"broken local reference: {destination}"))
    return errors


def find_duplicate_or_conflicting(
    paths: Sequence[str], root: Path
) -> tuple[list[str], list[str]]:
    """Find exact duplicate instruction files and literal modal contradictions."""
    duplicates: list[str] = []
    conflicts: list[str] = []
    by_content: dict[str, list[str]] = defaultdict(list)
    for relative in paths:
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        normalized = re.sub(r"\s+", " ", text).strip()
        if normalized:
            by_content[normalized].append(relative)
        actions: dict[str, set[str]] = defaultdict(set)
        for line in text.splitlines():
            match = CONFLICT_PATTERN.match(line)
            if not match:
                continue
            action = re.sub(
                r"[^a-z0-9]+",
                " ",
                f"{match.group('prefix')} {match.group('action')}".lower(),
            ).strip()
            if len(action) >= 12:
                modal = match.group("modal").lower()
                polarity = (
                    "negative"
                    if modal
                    in {"must not", "mustn't", "should not", "do not", "don't", "never"}
                    else "positive"
                )
                actions[action].add(polarity)
        for action, polarities in actions.items():
            if polarities == {"negative", "positive"}:
                conflicts.append(
                    f"{relative}: explicitly opposite directives for '{action}'"
                )
    for files in by_content.values():
        if len(files) > 1:
            duplicates.append(", ".join(sorted(files)))
    return duplicates, conflicts


def result(
    rule_id: str,
    status: str,
    message: str,
    files: Sequence[str] = (),
    remediation: str | None = None,
) -> CheckResult:
    return CheckResult(rule_id, status, message, tuple(sorted(set(files))), remediation)


def is_infrastructure_only(paths: Sequence[str]) -> bool:
    return bool(paths) and all(
        any(fnmatch.fnmatchcase(path, pattern) for pattern in INFRASTRUCTURE_PATTERNS)
        for path in paths
    )


def run_validation(
    args: argparse.Namespace, cwd: Path
) -> tuple[list[CheckResult], int, str | None]:
    """Coordinate independent discovery and validation stages."""
    try:
        root = find_repository_root(cwd)
        config = parse_config(root)
        changes = discover_changes(root, args.scope, args.base, args.head)
        instruction_paths = discover_instruction_files(
            root, config["instruction_globs"]
        )
    except (ValidationError, OSError, UnicodeError) as exc:
        failure = result(
            "AK005",
            "FAIL",
            "Invalid validator configuration or execution error",
            remediation="Check the Git worktree, revisions, and validator configuration.",
        )
        return (
            [
                result("AK001", "PASS", "Agent knowledge synchronization"),
                result("AK002", "PASS", "Agent and skill structure"),
                result("AKX001", "PASS", "Configured repository-specific validations"),
                result("AK003", "PASS", "Internal references"),
                result("AK004", "PASS", "Knowledge update relevance"),
                failure,
                result(
                    "AK006", "PASS", "No duplicate or conflicting instructions detected"
                ),
            ],
            2,
            str(exc),
        )

    excluded = [*DEFAULT_EXCLUDED_PATHS, *config["exclude_paths"]]
    considered = [
        change for change in changes if not is_excluded(change.path, excluded)
    ]
    changed_paths = [change.path for change in considered]
    infrastructure_only = is_infrastructure_only(changed_paths)
    knowledge_changes = [
        change.path
        for change in considered
        if is_instruction(change.path, config["instruction_globs"])
        and (root / change.path).is_file()
    ]
    project_changes = [
        change.path
        for change in considered
        if not is_instruction(change.path, config["instruction_globs"])
    ]
    substantive_files: list[str] = []
    suspicious_files: list[str] = []
    for path in knowledge_changes:
        added, removed = changed_content(root, args.scope, args.base, args.head, path)
        if substantive_update(added, removed, config["minimum_changed_lines"]):
            substantive_files.append(path)
        else:
            suspicious_files.append(path)

    if not considered or infrastructure_only:
        sync = result("AK001", "PASS", "Agent knowledge synchronization")
    elif substantive_files:
        sync = result(
            "AK001",
            "PASS",
            "Agent knowledge synchronized",
            substantive_files,
        )
    else:
        sync = result(
            "AK001",
            "FAIL",
            "Missing agent knowledge update",
            project_changes or changed_paths,
            "Update a relevant AGENTS.md, agent instruction, or SKILL.md with substantive operational guidance.",
        )

    structure_errors = validate_structure(
        root,
        instruction_paths,
        config["required_headings"],
        config["required_phrases"],
    )
    if structure_errors:
        structure = result(
            "AK002",
            "FAIL",
            "Invalid agent or skill structure",
            [path for path, _ in structure_errors],
            "Fix the required headings and simple frontmatter fields; frontmatter checks are partial and are not full YAML validation.",
        )
        structure_detail = [(path, message) for path, message in structure_errors]
    else:
        structure = result("AK002", "PASS", "Agent and skill structure valid")
        structure_detail = []

    skill_names: set[str] = set()
    for relative in instruction_paths:
        if PurePosixPath(relative).name != "SKILL.md":
            continue
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        fields = parse_frontmatter_fields(text)
        if fields and fields.get("name", "").strip():
            skill_names.add(fields["name"].strip())
    extension_errors = validate_extensions(root, instruction_paths, config, skill_names)
    if extension_errors:
        extension = result(
            "AKX001",
            "FAIL",
            "Configured repository-specific validation failed",
            [path for path, _ in extension_errors],
            "Correct the configured rule or update its documented repository-specific configuration.",
        )
        extension_detail = [("AKX001", message) for _, message in extension_errors]
    else:
        extension = result(
            "AKX001", "PASS", "Configured repository-specific validations passed"
        )
        extension_detail = []

    reference_errors = validate_references(root, instruction_paths)
    if reference_errors:
        references = result(
            "AK003",
            "FAIL",
            "Broken internal references",
            [path for path, _ in reference_errors],
            "Correct or remove the broken repository-relative Markdown link.",
        )
        reference_detail = [(path, message) for path, message in reference_errors]
    else:
        references = result("AK003", "PASS", "Internal references valid")
        reference_detail = []

    if suspicious_files:
        relevance = result(
            "AK004",
            "FAIL",
            "Suspicious knowledge update: no effective content change detected",
            suspicious_files,
            "Replace cosmetic or metadata-only edits with substantive operational guidance.",
        )
    elif substantive_files:
        relevance = result(
            "AK004",
            "WARN",
            "Manual relevance review recommended",
            substantive_files,
            "Confirm that the instruction update is relevant and reusable; automation cannot prove semantic correctness.",
        )
    else:
        relevance = result("AK004", "PASS", "No suspicious knowledge update detected")

    configuration = result(
        "AK005", "PASS", "Validator configuration and execution valid"
    )
    duplicates, conflicts = find_duplicate_or_conflicting(instruction_paths, root)
    if duplicates or conflicts:
        files: list[str] = []
        files.extend(path for group in duplicates for path in group.split(", "))
        files.extend(item.split(":", 1)[0] for item in conflicts)
        detail = []
        if duplicates:
            detail.append("exact duplicate files: " + "; ".join(duplicates))
        detail.extend(conflicts)
        conflict_result = result(
            "AK006",
            "WARN",
            "Potential duplicate or conflicting instructions found",
            files,
            "Review the listed instructions and consolidate or clarify only when their scopes truly overlap.",
        )
        conflict_detail = detail
    else:
        conflict_result = result(
            "AK006", "PASS", "No duplicate or conflicting instructions detected"
        )
        conflict_detail = []

    details = (
        structure_detail
        + extension_detail
        + reference_detail
        + [("AK006", message) for message in conflict_detail]
    )
    results = [
        sync,
        structure,
        extension,
        references,
        relevance,
        configuration,
        conflict_result,
    ]
    return results, 0, json.dumps(details, ensure_ascii=False)


def make_report(checks: Sequence[CheckResult]) -> dict[str, Any]:
    errors = [asdict(item) for item in checks if item.status == "FAIL"]
    warnings = [asdict(item) for item in checks if item.status == "WARN"]
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "status": "FAIL" if errors else "PASS",
        "summary": {"errors": len(errors), "warnings": len(warnings)},
        "checks": [asdict(item) for item in checks],
        "errors": errors,
        "warnings": warnings,
    }


def print_report(report: dict[str, Any], output_format: str) -> None:
    """Write stable text or JSON to stdout."""
    if output_format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    for check in report["checks"]:
        label = check["status"]
        print(f"[{label}] {check['rule_id']} - {check['message']}")
        if check["files"]:
            print("  Files: " + ", ".join(check["files"]))
        if check["remediation"]:
            print("  Action: " + check["remediation"])
    print("\nAgent Knowledge Validation")
    print(f"Status: {report['status']}")
    print(f"Errors: {report['summary']['errors']}")
    print(f"Warnings: {report['summary']['warnings']}")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"Validate Agent Knowledge contract {CONTRACT_VERSION} using only Python's standard library."
        )
    )
    parser.add_argument("--scope", choices=("worktree", "range"), required=True)
    parser.add_argument("--base", help="base Git revision; required with --scope range")
    parser.add_argument("--head", help="head Git revision; required with --scope range")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    if args.scope == "range" and (not args.base or not args.head):
        parser.error("--scope range requires both --base and --head")
    if args.scope == "worktree" and (args.base or args.head):
        parser.error("--base and --head are only valid with --scope range")

    checks, execution_code, detail = run_validation(args, Path.cwd())
    report = make_report(checks)
    print_report(report, args.format)
    if execution_code == 2:
        if args.format == "json":
            print(f"validator execution error: {detail}", file=sys.stderr)
        return 2
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
