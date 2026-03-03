#!/usr/bin/env python3
"""Validate Gentoo docs for required sections, links, and script references."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


RE_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
RE_SCRIPT_REF = re.compile(r"(scripts/gentoo/[A-Za-z0-9._-]+)")


@dataclass(frozen=True)
class DocRequirement:
    path: Path
    required_headers: Sequence[str]


REQUIRED_DOCS: Sequence[DocRequirement] = (
    DocRequirement(
        path=Path("docs/gentoo/USER-GUIDE.md"),
        required_headers=(
            "# Gentoo Validation User Guide",
            "## Quick Start",
            "## Troubleshooting",
        ),
    ),
    DocRequirement(
        path=Path("docs/gentoo/CONTRIBUTING.md"),
        required_headers=(
            "# Gentoo Validation Contributing Guide",
            "## Adding Packages",
            "## Reporting Issues",
        ),
    ),
    DocRequirement(
        path=Path("docs/gentoo/REFERENCE.md"),
        required_headers=(
            "# Gentoo Validation Technical Reference",
            "## Configuration Options",
            "## CLI Reference",
        ),
    ),
    DocRequirement(
        path=Path("docs/gentoo/VALIDATION-REPORT-TEMPLATE.md"),
        required_headers=(
            "# FrankenLibC Gentoo Ecosystem Validation Report",
            "## Executive Summary",
            "## Artifact Index",
        ),
    ),
    DocRequirement(
        path=Path("docs/gentoo/OPERATIONS.md"),
        required_headers=(
            "# Gentoo Validation Operations Guide",
            "## Running Validation",
            "## Incident Response",
        ),
    ),
    DocRequirement(
        path=Path("docs/gentoo/FAQ.md"),
        required_headers=(
            "# Gentoo Validation FAQ",
            "## How do I generate a publication-ready markdown report?",
            "## How do I verify Gentoo docs and links are valid?",
        ),
    ),
)


def is_external_link(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith("http://") or lowered.startswith("https://") or lowered.startswith("mailto:")


def split_link_target(target: str) -> Tuple[str, str]:
    if "#" not in target:
        return target, ""
    path, anchor = target.split("#", 1)
    return path, anchor


def validate_file_presence(requirements: Sequence[DocRequirement], repo_root: Path) -> List[str]:
    missing: List[str] = []
    for req in requirements:
        if not (repo_root / req.path).exists():
            missing.append(str(req.path))
    return missing


def validate_required_headers(requirements: Sequence[DocRequirement], repo_root: Path) -> List[Dict[str, object]]:
    issues: List[Dict[str, object]] = []
    for req in requirements:
        doc_path = repo_root / req.path
        if not doc_path.exists():
            continue
        text = doc_path.read_text(encoding="utf-8")
        for header in req.required_headers:
            if header not in text:
                issues.append(
                    {
                        "file": str(req.path),
                        "missing_header": header,
                    }
                )
    return issues


def validate_links(requirements: Sequence[DocRequirement], repo_root: Path) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    for req in requirements:
        doc_path = repo_root / req.path
        if not doc_path.exists():
            continue
        text = doc_path.read_text(encoding="utf-8")
        for raw_target in RE_LINK.findall(text):
            target = raw_target.strip()
            if not target or target.startswith("#") or is_external_link(target):
                continue
            rel_path, _anchor = split_link_target(target)
            if not rel_path:
                continue
            resolved = (doc_path.parent / rel_path).resolve()
            if not resolved.exists():
                issues.append(
                    {
                        "file": str(req.path),
                        "target": target,
                        "reason": "missing_path",
                    }
                )
    return issues


def validate_script_references(requirements: Sequence[DocRequirement], repo_root: Path) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    for req in requirements:
        doc_path = repo_root / req.path
        if not doc_path.exists():
            continue
        text = doc_path.read_text(encoding="utf-8")
        for script_rel in sorted(set(RE_SCRIPT_REF.findall(text))):
            script_path = repo_root / script_rel
            if not script_path.exists():
                issues.append(
                    {
                        "file": str(req.path),
                        "script": script_rel,
                        "reason": "missing_script",
                    }
                )
    return issues


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate docs/gentoo markdown docs.")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--output", default="", help="Optional JSON report output path")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when issues are present")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()

    missing_files = validate_file_presence(REQUIRED_DOCS, repo_root)
    missing_headers = validate_required_headers(REQUIRED_DOCS, repo_root)
    broken_links = validate_links(REQUIRED_DOCS, repo_root)
    missing_scripts = validate_script_references(REQUIRED_DOCS, repo_root)

    report: Dict[str, object] = {
        "schema_version": "v1",
        "tool": "scripts/gentoo/validate-docs.py",
        "missing_files": missing_files,
        "missing_headers": missing_headers,
        "broken_links": broken_links,
        "missing_scripts": missing_scripts,
        "summary": {
            "missing_file_count": len(missing_files),
            "missing_header_count": len(missing_headers),
            "broken_link_count": len(broken_links),
            "missing_script_count": len(missing_scripts),
        },
    }

    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    has_issues = any(
        (
            missing_files,
            missing_headers,
            broken_links,
            missing_scripts,
        )
    )
    if args.strict and has_issues:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
