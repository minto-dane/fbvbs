#!/usr/bin/env python3
"""FBVBS __FRAMAC__ Stub Synchronisation Checker

Detects drift between __FRAMAC__ stubs and production code.

Checks performed:
  1. STRUCT_ZERO: finds compound-literal zeroing in production (#else) paths
     and verifies the matching __FRAMAC__ stub has a SYNC marker.
  2. FULL_STUB: finds __FRAMAC__ blocks that replace an entire function body
     (return early) and verifies a SYNC marker exists.
  3. SIZE_GUARD: for STRUCT_ZERO blocks, verifies that the __FRAMAC__ block
     contains a _Static_assert on struct size (compile-time drift guard).

Reports:
  - Per-file and overall coverage statistics.
  - List of blocks missing SYNC markers or size guards.

Usage:
    python3 tools/check_framac_stubs.py [--strict] [--quiet]
      --strict  exit non-zero if ANY high-risk block lacks SYNC
      --quiet   suppress per-block detail, only print summary

Exit codes: 0 = clean, 1 = issues found (--strict), 2 = usage error.
"""

import os
import re
import sys
from collections import defaultdict

HYPERVISOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(HYPERVISOR_DIR, "src")
INCLUDE_DIR = os.path.join(HYPERVISOR_DIR, "include")

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
FRAMAC_OPEN = re.compile(
    r"^\s*#\s*if(?:def\s+__FRAMAC__|(?:\s+defined\s*\(\s*__FRAMAC__\s*\)))"
)
FRAMAC_IFNDEF = re.compile(r"^\s*#\s*ifndef\s+__FRAMAC__")
ELSE_DIRECTIVE = re.compile(r"^\s*#\s*else\b")
ENDIF_DIRECTIVE = re.compile(r"^\s*#\s*endif\b")
COMPOUND_ZERO = re.compile(
    r"=\s*\(struct\s+(\w+)\)\s*\{0\}"
)
SYNC_MARKER = re.compile(r"\bSYNC\b", re.IGNORECASE)
FULL_STUB_RETURN = re.compile(r"^\s*return\b")
STATIC_ASSERT = re.compile(r"_Static_assert\s*\(")

# Classify block risk
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"


def parse_framac_blocks(filepath):
    """Parse a C file and extract all __FRAMAC__ conditional blocks.

    Returns a list of dicts with keys:
      line      - start line (1-based)
      end_line  - end line (1-based)
      kind      - 'ifdef' or 'ifndef'
      framac_lines  - lines inside the __FRAMAC__ true-branch
      else_lines    - lines inside the #else branch (if any)
      has_sync      - bool
      has_size_guard - bool
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i]
        is_ifdef = FRAMAC_OPEN.search(line)
        is_ifndef = FRAMAC_IFNDEF.search(line)

        if not is_ifdef and not is_ifndef:
            i += 1
            continue

        start = i + 1  # 1-based
        kind = "ifdef" if is_ifdef else "ifndef"
        depth = 1
        framac_lines = []
        else_lines = []
        in_else = False
        j = i + 1

        while j < len(lines) and depth > 0:
            ln = lines[j]
            if re.match(r"^\s*#\s*if", ln):
                depth += 1
            elif ENDIF_DIRECTIVE.match(ln):
                depth -= 1
                if depth == 0:
                    break
            elif ELSE_DIRECTIVE.match(ln) and depth == 1:
                in_else = True
                j += 1
                continue
            elif re.match(r"^\s*#\s*elif\b", ln) and depth == 1:
                in_else = True
                j += 1
                continue

            if depth >= 1:
                if in_else:
                    else_lines.append(ln)
                else:
                    framac_lines.append(ln)
            j += 1

        end = j + 1  # 1-based

        # For ifdef: framac_lines = FRAMAC path, else_lines = production
        # For ifndef: framac_lines = production, else_lines = FRAMAC
        if kind == "ifndef":
            framac_lines, else_lines = else_lines, framac_lines

        framac_text = "".join(framac_lines)
        else_text = "".join(else_lines)

        # Also check up to 5 lines before the directive for SYNC comments
        # (handles `/* SYNC: ... */\n#ifndef __FRAMAC__` pattern)
        preamble_start = max(0, i - 5)
        preamble_text = "".join(lines[preamble_start:i])

        blocks.append({
            "line": start,
            "end_line": end,
            "kind": kind,
            "framac_text": framac_text,
            "else_text": else_text,
            "has_sync": bool(SYNC_MARKER.search(framac_text) or
                             SYNC_MARKER.search(preamble_text)),
            "has_size_guard": bool(STATIC_ASSERT.search(framac_text)),
        })

        i = j + 1

    return blocks


def classify_block(block):
    """Classify a block and return (category, risk, struct_name_or_None)."""
    else_text = block["else_text"]
    framac_text = block["framac_text"]

    # STRUCT_ZERO: production path has compound-literal zeroing
    m = COMPOUND_ZERO.search(else_text)
    if m:
        return "STRUCT_ZERO", RISK_HIGH, m.group(1)

    # For ifndef blocks, the roles are swapped in our storage
    # but parse already handles that. Check framac_text for
    # patterns that indicate FULL_STUB
    framac_stripped = framac_text.strip()

    # FULL_STUB: FRAMAC block returns early (replaces body)
    if FULL_STUB_RETURN.search(framac_text):
        # Check if this looks like a real stub (has (void) casts or
        # returns a value) vs a simple guard
        void_casts = framac_text.count("(void)")
        if void_casts >= 2 or len(framac_text.splitlines()) > 5:
            return "FULL_STUB", RISK_HIGH, None

    # HW_STUB: assembly or hardware operation
    if any(kw in else_text.lower() for kw in
           ["asm", "__asm__", "cpuid", "vmxon", "vmwrite", "vmread",
            "rdmsr", "wrmsr", "invlpg", "invept", "invpcid"]):
        return "HW_STUB", RISK_MEDIUM, None

    # LOOP_SIMPLIFY: else has more loop constructs
    if else_text.count("for") > framac_text.count("for") + 1:
        return "LOOP_SIMPLIFY", RISK_MEDIUM, None

    # CONTROL_FLOW: infinite loop replacement
    if "for(;;)" in else_text or "while(1)" in else_text:
        return "CONTROL_FLOW", RISK_LOW, None

    # SUPPRESS: simple (void) or short blocks
    if len(framac_text.strip().splitlines()) <= 3:
        return "SUPPRESS", RISK_LOW, None

    return "OTHER", RISK_LOW, None


def scan_file(filepath):
    """Scan a single file and return list of findings."""
    blocks = parse_framac_blocks(filepath)
    findings = []
    for b in blocks:
        cat, risk, sname = classify_block(b)
        findings.append({
            "file": os.path.relpath(filepath, HYPERVISOR_DIR),
            "line": b["line"],
            "end_line": b["end_line"],
            "category": cat,
            "risk": risk,
            "struct_name": sname,
            "has_sync": b["has_sync"],
            "has_size_guard": b["has_size_guard"],
        })
    return findings


def main():
    strict = "--strict" in sys.argv
    quiet = "--quiet" in sys.argv

    # Collect all C source and header files
    files = []
    for d in [SRC_DIR, INCLUDE_DIR]:
        try:
            for root, _dirs, fnames in os.walk(d):
                for fn in sorted(fnames):
                    if fn.endswith((".c", ".h")):
                        files.append(os.path.join(root, fn))
        except FileNotFoundError:
            pass

    all_findings = []
    for fp in files:
        all_findings.extend(scan_file(fp))

    # Statistics
    total = len(all_findings)
    by_cat = defaultdict(int)
    by_risk = defaultdict(int)
    high_risk_no_sync = []
    struct_zero_no_guard = []

    for f in all_findings:
        by_cat[f["category"]] += 1
        by_risk[f["risk"]] += 1
        if f["risk"] == RISK_HIGH and not f["has_sync"]:
            high_risk_no_sync.append(f)
        if f["category"] == "STRUCT_ZERO" and not f["has_size_guard"]:
            struct_zero_no_guard.append(f)

    synced = sum(1 for f in all_findings if f["has_sync"])

    # Report
    print("=" * 70)
    print("FBVBS __FRAMAC__ Stub Synchronisation Report")
    print("=" * 70)
    print()
    print(f"Total __FRAMAC__ blocks: {total}")
    print(f"With SYNC marker:        {synced} ({100*synced//max(total,1)}%)")
    print()
    print("Category breakdown:")
    for cat in ["STRUCT_ZERO", "FULL_STUB", "HW_STUB", "LOOP_SIMPLIFY",
                "CONTROL_FLOW", "SUPPRESS", "OTHER"]:
        cnt = by_cat.get(cat, 0)
        if cnt:
            print(f"  {cat:20s} {cnt:4d}")
    print()
    print("Risk breakdown:")
    for risk in [RISK_HIGH, RISK_MEDIUM, RISK_LOW]:
        cnt = by_risk.get(risk, 0)
        if cnt:
            print(f"  {risk:20s} {cnt:4d}")
    print()

    # High-risk blocks without SYNC
    if high_risk_no_sync:
        print(f"HIGH-RISK blocks without SYNC marker: {len(high_risk_no_sync)}")
        if not quiet:
            for f in high_risk_no_sync:
                sn = f" [{f['struct_name']}]" if f["struct_name"] else ""
                print(f"  {f['file']}:{f['line']} "
                      f"{f['category']}{sn}")
        print()

    # STRUCT_ZERO blocks without _Static_assert size guard
    if struct_zero_no_guard:
        print(f"STRUCT_ZERO blocks without _Static_assert size guard: "
              f"{len(struct_zero_no_guard)}")
        if not quiet:
            for f in struct_zero_no_guard:
                print(f"  {f['file']}:{f['line']} "
                      f"struct {f['struct_name']}")
        print()

    # Summary verdict
    issues = len(high_risk_no_sync)
    if issues == 0:
        print("PASS: All high-risk __FRAMAC__ blocks have SYNC markers.")
    else:
        print(f"WARN: {issues} high-risk blocks lack SYNC markers.")
        if strict:
            print("FAIL: --strict mode, exiting with error.")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
