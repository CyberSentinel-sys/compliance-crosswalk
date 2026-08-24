#!/usr/bin/env python3
"""compliance-crosswalk — map security controls across multiple public frameworks.

Given a set of security controls an organization has *in place*, this tool maps
them across several public security / OT frameworks at once and reports, per
framework, how much of that framework's (illustrative, public-subset) structure
is covered and which requirement IDs remain as gaps.

Thesis: one assessment can answer to every framework a critical-infrastructure
operator is measured against — IEC 62443-3-3, NIST SP 800-82, NIST CSF, and the
CISA Cross-Sector Cybersecurity Performance Goals (CPGs).

The bundled framework data and crosswalk are an ILLUSTRATIVE public-reference
starter, not an authoritative or proprietary mapping. This tool organizes
coverage against a framework's structure; it is NOT a compliance certification,
audit, or legal advice. Bring your own crosswalk for real use.

Standard library only. Python 3.8+.
"""

import argparse
import json
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FRAMEWORKS: "OrderedDict[str, Tuple[str, str]]" = OrderedDict(
    [
        # key -> (data filename, human label)
        ("iec-62443", ("iec-62443-3-3.json", "IEC 62443-3-3")),
        ("nist-800-82", ("nist-800-82.json", "NIST SP 800-82")),
        ("nist-csf", ("nist-csf.json", "NIST CSF 2.0")),
        ("cisa-cpg", ("cisa-cpg.json", "CISA Cross-Sector CPGs")),
    ]
)

DATA_DIR = Path(__file__).resolve().parent / "data"


class InputError(Exception):
    """Raised when user-supplied input cannot be used."""


def load_json(path: Path) -> object:
    """Load a JSON file, raising InputError with a clear message on failure."""
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise InputError("file not found: {}".format(path))
    except json.JSONDecodeError as exc:
        raise InputError("invalid JSON in {}: {}".format(path, exc))


def load_framework(key: str) -> "OrderedDict[str, str]":
    """Return an ordered {requirement_id: title} map for a framework key."""
    filename, _label = FRAMEWORKS[key]
    raw = load_json(DATA_DIR / "frameworks" / filename)
    requirements: "OrderedDict[str, str]" = OrderedDict()
    items = raw.get("requirements", raw) if isinstance(raw, dict) else raw
    for item in items:
        requirements[item["id"]] = item.get("title", "")
    return requirements


def load_crosswalk() -> Dict[str, Dict[str, List[str]]]:
    """Return {control_id: {framework_key: [requirement_id, ...]}}.

    The crosswalk file carries metadata under leading underscore keys (e.g.
    "_note"); those are ignored here.
    """
    raw = load_json(DATA_DIR / "crosswalk.json")
    if not isinstance(raw, dict):
        raise InputError("crosswalk.json must be a JSON object")
    controls: Dict[str, Dict[str, List[str]]] = {}
    for key, value in raw.items():
        if key.startswith("_"):
            continue
        controls[key] = value
    return controls


def read_controls_in_place(path: Path) -> List[str]:
    """Read the list of control ids that are 'in place' from the input file.

    Accepts either a bare JSON list of ids, or an object with a
    "controls_in_place" key holding that list.
    """
    raw = load_json(path)
    if isinstance(raw, dict):
        controls = raw.get("controls_in_place")
    else:
        controls = raw
    if not isinstance(controls, list) or not all(
        isinstance(c, str) for c in controls
    ):
        raise InputError(
            "input must be a JSON list of control ids, or an object with a "
            '"controls_in_place" list of strings'
        )
    return controls


def compute_coverage(
    controls_in_place: List[str],
    crosswalk: Dict[str, Dict[str, List[str]]],
    framework_keys: List[str],
) -> "OrderedDict[str, dict]":
    """Compute per-framework coverage for the controls that are in place.

    Returns an ordered map: framework_key -> {
        label, total, covered, percent, covered_ids, gap_ids,
        satisfied_by: {requirement_id: [control_id, ...]}
    }.
    """
    result: "OrderedDict[str, dict]" = OrderedDict()
    in_place = set(controls_in_place)

    for fkey in framework_keys:
        requirements = load_framework(fkey)
        satisfied_by: Dict[str, List[str]] = {}

        for control_id in controls_in_place:
            mapping = crosswalk.get(control_id, {})
            for req_id in mapping.get(fkey, []):
                if req_id in requirements:
                    satisfied_by.setdefault(req_id, []).append(control_id)

        covered_ids = [rid for rid in requirements if rid in satisfied_by]
        gap_ids = [rid for rid in requirements if rid not in satisfied_by]
        total = len(requirements)
        covered = len(covered_ids)
        percent = round(100.0 * covered / total, 1) if total else 0.0

        result[fkey] = {
            "label": FRAMEWORKS[fkey][1],
            "total": total,
            "covered": covered,
            "percent": percent,
            "covered_ids": covered_ids,
            "gap_ids": gap_ids,
            "gap_titles": OrderedDict(
                (rid, requirements[rid]) for rid in gap_ids
            ),
            "satisfied_by": satisfied_by,
        }
    return result


def find_unknown_controls(
    controls_in_place: List[str], crosswalk: Dict[str, Dict[str, List[str]]]
) -> List[str]:
    """Return control ids that are not present in the bundled crosswalk."""
    return [c for c in controls_in_place if c not in crosswalk]


def render_text(coverage: "OrderedDict[str, dict]", unknown: List[str]) -> str:
    """Render a plain-text coverage report."""
    lines: List[str] = []
    lines.append("Compliance Crosswalk — coverage report")
    lines.append("(illustrative public-reference data; not a certification)")
    lines.append("")
    for fkey, data in coverage.items():
        lines.append(
            "{label} [{key}]".format(label=data["label"], key=fkey)
        )
        lines.append(
            "  coverage: {covered}/{total} ({percent}%)".format(**data)
        )
        if data["gap_ids"]:
            lines.append("  gaps ({}):".format(len(data["gap_ids"])))
            for rid in data["gap_ids"]:
                lines.append(
                    "    - {id}  {title}".format(
                        id=rid, title=data["gap_titles"][rid]
                    )
                )
        else:
            lines.append("  gaps: none")
        lines.append("")
    if unknown:
        lines.append(
            "WARNING: {n} unknown control id(s) not in crosswalk (ignored): "
            "{ids}".format(n=len(unknown), ids=", ".join(unknown))
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(
    coverage: "OrderedDict[str, dict]", unknown: List[str]
) -> str:
    """Render a Markdown coverage report."""
    lines: List[str] = []
    lines.append("# Compliance Crosswalk — coverage report")
    lines.append("")
    lines.append(
        "> Illustrative public-reference data. Organizes coverage against "
        "each framework's structure; not a compliance certification, audit, "
        "or legal advice."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Framework | Key | Covered | Total | Coverage |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for fkey, data in coverage.items():
        lines.append(
            "| {label} | `{key}` | {covered} | {total} | {percent}% |".format(
                key=fkey, **data
            )
        )
    lines.append("")
    for fkey, data in coverage.items():
        lines.append("## {label} (`{key}`)".format(key=fkey, **data))
        lines.append("")
        lines.append(
            "Coverage: **{covered}/{total} ({percent}%)**".format(**data)
        )
        lines.append("")
        if data["gap_ids"]:
            lines.append("Gaps:")
            lines.append("")
            for rid in data["gap_ids"]:
                lines.append(
                    "- `{id}` — {title}".format(
                        id=rid, title=data["gap_titles"][rid]
                    )
                )
        else:
            lines.append("No gaps in the bundled subset.")
        lines.append("")
    if unknown:
        lines.append("## Warnings")
        lines.append("")
        lines.append(
            "Unknown control id(s) not in the crosswalk (ignored): "
            + ", ".join("`{}`".format(c) for c in unknown)
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_json_report(
    coverage: "OrderedDict[str, dict]", unknown: List[str]
) -> dict:
    """Build a JSON-serializable report structure."""
    frameworks = OrderedDict()
    for fkey, data in coverage.items():
        frameworks[fkey] = {
            "label": data["label"],
            "total": data["total"],
            "covered": data["covered"],
            "percent": data["percent"],
            "covered_ids": data["covered_ids"],
            "gap_ids": data["gap_ids"],
            "satisfied_by": data["satisfied_by"],
        }
    return {
        "disclaimer": (
            "Illustrative public-reference data. Organizes coverage against "
            "each framework's structure; not a compliance certification, "
            "audit, or legal advice."
        ),
        "unknown_controls": unknown,
        "frameworks": frameworks,
    }


def resolve_framework_keys(selector: str) -> List[str]:
    """Turn the --framework selector into a list of framework keys."""
    if selector == "all":
        return list(FRAMEWORKS.keys())
    if selector not in FRAMEWORKS:
        raise InputError(
            "unknown framework '{sel}' (choose from: {choices}, all)".format(
                sel=selector, choices=", ".join(FRAMEWORKS.keys())
            )
        )
    return [selector]


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="crosswalk.py",
        description=(
            "Map security controls in place across multiple public security / "
            "OT frameworks and report per-framework coverage and gaps."
        ),
    )
    parser.add_argument(
        "controls",
        help="Path to a controls-in-place JSON file (list of control ids).",
    )
    parser.add_argument(
        "--framework",
        default="all",
        help=(
            "Framework to report on: "
            + ", ".join(FRAMEWORKS.keys())
            + ", or all (default: all)."
        ),
    )
    parser.add_argument(
        "--format",
        default="text",
        choices=["text", "markdown", "json"],
        help="Output format (default: text).",
    )
    return parser


def run(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns a process exit code (0 ok, 2 input error)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        framework_keys = resolve_framework_keys(args.framework)
        crosswalk = load_crosswalk()
        controls_in_place = read_controls_in_place(Path(args.controls))
    except InputError as exc:
        sys.stderr.write("error: {}\n".format(exc))
        return 2

    unknown = find_unknown_controls(controls_in_place, crosswalk)
    coverage = compute_coverage(controls_in_place, crosswalk, framework_keys)

    if args.format == "json":
        report = build_json_report(coverage, unknown)
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    elif args.format == "markdown":
        sys.stdout.write(render_markdown(coverage, unknown))
    else:
        sys.stdout.write(render_text(coverage, unknown))
    return 0


if __name__ == "__main__":
    sys.exit(run())
