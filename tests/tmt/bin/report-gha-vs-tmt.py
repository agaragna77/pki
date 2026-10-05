#!/usr/bin/env python3
"""Report GHA↔TMT parity for Dogtag *-test.yml workflows.

For each stem (or all) writes to JARVIS POCs directory:
  {stem}-gha-vs-tmt-steps.txt      180-col side-by-side
  {stem}-gha-vs-tmt-prepare.txt    GHA build/retrieve vs TMT prepare
  {stem}-gha-vs-tmt-results.txt    placeholder status
  {stem}-differences-gha-vs-tmt.md short narrative

Global report:
  dogtag-gha-tmt-global-report.md
  dogtag-gha-tmt-global-inventory.json
"""
import fnmatch
import json
import os
import re
import sys
import textwrap

import yaml


WORKFLOWS_DIR = ".github/workflows"
TMT_PLANS_DIR = "tests/tmt/plans"
TMT_TESTS_DIR = "tests/tmt"
JARVIS_DIR = "/home/agaragna/Projects/JARVIS/POCs/IDM-8254"

EXCLUDE_PATTERNS = [
    "*-tests.yml",
    "build.yml",
    "publish.yml",
    "stale.yml",
    "wait-for-build.yml",
    "sonarcloud*",
]


def find_repo_root():
    d = os.path.dirname(os.path.abspath(__file__))
    while d != "/":
        if os.path.isdir(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return os.getcwd()


def is_excluded(filename):
    for pat in EXCLUDE_PATTERNS:
        if fnmatch.fnmatch(filename, pat):
            return True
    return False


def stem_from_filename(filename):
    return filename.removesuffix(".yml")


def get_gha_steps(repo, filename):
    """Parse GHA workflow and return list of step dicts."""
    wf_path = os.path.join(repo, WORKFLOWS_DIR, filename)
    with open(wf_path) as fh:
        data = yaml.safe_load(fh)

    workflow_name = data.get("name", stem_from_filename(filename))
    jobs = data.get("jobs", {})
    job_data = None
    for jn in ("test", "Test"):
        if jn in jobs:
            job_data = jobs[jn]
            break
    if job_data is None:
        job_data = next(iter(jobs.values()))

    return workflow_name, job_data.get("steps", [])


def get_tmt_banners(repo, stem):
    """Extract step banners from test.sh.

    Matches generated ``step "Name"`` / ``step 'Name'`` / unquoted ``step Name``,
    and falls back to ``echo "==== ... ===="`` or hand-ported ``echo "==> ..."``.
    """
    test_sh = os.path.join(repo, TMT_TESTS_DIR, stem, "test.sh")
    banners = []
    if not os.path.isfile(test_sh):
        return banners
    with open(test_sh) as fh:
        for line in fh:
            s = line.strip()
            if re.match(r"^step\(\)\s*\{", s):
                continue
            m = re.match(r'^step\s+"(.+)"\s*$', s)
            if m:
                banners.append(m.group(1))
                continue
            m = re.match(r"^step\s+'(.+)'\s*$", s)
            if m:
                banners.append(m.group(1))
                continue
            m = re.match(r"^step\s+([^\"'].+)$", s)
            if m and not m.group(1).startswith("("):
                banners.append(m.group(1).strip())
                continue
            m = re.match(r'^echo\s+"====\s*(.+?)\s*===="\s*$', s)
            if m:
                text = m.group(1)
                if not re.search(r"\b(PASSED|FAILED)\b", text):
                    banners.append(text)
                continue
            m = re.match(r"^echo\s+'====\s*(.+?)\s*===='\s*$", s)
            if m:
                text = m.group(1)
                if not re.search(r"\b(PASSED|FAILED)\b", text):
                    banners.append(text)
                continue
            m = re.match(r'^echo\s+"==>\s*(.+)"\s*$', s)
            if m:
                text = m.group(1)
                if not re.search(r"\b(PASSED|FAILED)\b", text):
                    banners.append(text)
                continue
            m = re.match(r"^echo\s+'==>\s*(.+)'\s*$", s)
            if m:
                text = m.group(1)
                if not re.search(r"\b(PASSED|FAILED)\b", text):
                    banners.append(text)
    return banners


def classify_tmt_status(repo, stem):
    """Determine status of TMT test: stub-fail, generated, hand-ported, missing."""
    test_sh = os.path.join(repo, TMT_TESTS_DIR, stem, "test.sh")
    if not os.path.isfile(test_sh):
        return "MISSING"

    with open(test_sh) as fh:
        content = fh.read()

    if "# Generated TMT port" in content:
        if 'echo "FAIL: unimplemented GHA step' in content:
            return "STUB_FAIL"
        return "GENERATED"
    return "HAND_PORTED"


def side_by_side(left_lines, right_lines, width=180):
    """Create a side-by-side view."""
    col = width // 2 - 2
    rows = max(len(left_lines), len(right_lines))
    out = []
    header = f"{'GHA Step':<{col}} | {'TMT Banner':<{col}}"
    out.append(header)
    out.append("-" * len(header))
    for i in range(rows):
        l = left_lines[i] if i < len(left_lines) else ""
        r = right_lines[i] if i < len(right_lines) else ""
        l = l[:col]
        r = r[:col]
        out.append(f"{l:<{col}} | {r:<{col}}")
    return "\n".join(out) + "\n"


def write_stem_reports(repo, stem, filename):
    """Write per-stem report files."""
    os.makedirs(JARVIS_DIR, exist_ok=True)

    workflow_name, gha_steps = get_gha_steps(repo, filename)
    gha_names = [s.get("name", "<unnamed>") for s in gha_steps]
    tmt_banners = get_tmt_banners(repo, stem)
    status = classify_tmt_status(repo, stem)

    # Steps side-by-side
    steps_path = os.path.join(JARVIS_DIR, f"{stem}-gha-vs-tmt-steps.txt")
    with open(steps_path, "w") as fh:
        fh.write(f"# {workflow_name}: GHA steps vs TMT banners\n\n")
        fh.write(side_by_side(gha_names, tmt_banners))

    # Prepare comparison
    prepare_path = os.path.join(JARVIS_DIR, f"{stem}-gha-vs-tmt-prepare.txt")
    gha_prepare = []
    for s in gha_steps:
        name = s.get("name", "")
        uses = s.get("uses", "")
        if uses and "checkout" in uses:
            gha_prepare.append(f"GHA: {name} → actions/checkout")
        elif uses and "cache" in uses:
            gha_prepare.append(f"GHA: {name} → actions/cache (image tar)")
        elif "docker load" in (s.get("run", "") or ""):
            gha_prepare.append(f"GHA: {name} → docker load --input *.tar")
        elif name and ("install" in name.lower() or "build" in name.lower() or "set up" in name.lower()):
            gha_prepare.append(f"GHA: {name}")

    tmt_prepare = [
        "TMT: require-docker → command -v docker",
        "TMT: build-pki-runner → tests/tmt/bin/build-pki-runner.sh",
    ]

    with open(prepare_path, "w") as fh:
        fh.write(f"# {workflow_name}: Prepare comparison\n\n")
        fh.write("## GHA Build/Retrieve\n")
        for line in gha_prepare:
            fh.write(f"  {line}\n")
        fh.write("\n## TMT Prepare\n")
        for line in tmt_prepare:
            fh.write(f"  {line}\n")

    # Results
    results_path = os.path.join(JARVIS_DIR, f"{stem}-gha-vs-tmt-results.txt")
    with open(results_path, "w") as fh:
        fh.write(f"# {workflow_name}: Results\n\n")
        fh.write(f"TMT Status: {status}\n")
        fh.write(f"Run Status: NOT_RUN\n\n")
        for name in gha_names:
            fh.write(f"  {name:<60s} NOT_RUN\n")

    # Differences narrative
    diff_path = os.path.join(JARVIS_DIR, f"{stem}-differences-gha-vs-tmt.md")
    with open(diff_path, "w") as fh:
        fh.write(f"# {workflow_name}: GHA↔TMT Differences\n\n")
        fh.write(f"**Stem:** `{stem}`\n")
        fh.write(f"**TMT status:** {status}\n\n")

        fh.write("## Prepare\n\n")
        fh.write("| Aspect | GHA | TMT |\n")
        fh.write("|--------|-----|-----|\n")
        fh.write("| Source | Pre-built image from `actions/cache` | `build-pki-runner.sh` builds from Dockerfile |\n")
        fh.write("| Checkout | `actions/checkout` | Repo at `$TMT_TREE` |\n")

        fh.write("\n## Steps\n\n")
        fh.write(f"- GHA steps: {len(gha_names)}\n")
        fh.write(f"- TMT banners: {len(tmt_banners)}\n")

        # Count unimplemented
        test_sh = os.path.join(repo, TMT_TESTS_DIR, stem, "test.sh")
        unimpl = 0
        if os.path.isfile(test_sh):
            with open(test_sh) as tf:
                for line in tf:
                    if "FAIL: unimplemented GHA step" in line:
                        unimpl += 1
        if unimpl:
            fh.write(f"- Unimplemented (will FAIL): {unimpl}\n")

        fh.write("\n## Notes\n\n")
        if status == "HAND_PORTED":
            fh.write("Hand-ported test — high fidelity port of GHA workflow.\n")
        elif status == "GENERATED":
            fh.write("Generator-produced test — all GHA steps translated; no known unimplemented actions.\n")
        elif status == "STUB_FAIL":
            fh.write("Generator-produced test with stub-fail steps — some GHA actions could not be auto-translated and will `exit 1`.\n")
        else:
            fh.write("TMT test is missing.\n")

    return {
        "stem": stem,
        "workflow": filename,
        "workflow_name": workflow_name,
        "gha_steps": len(gha_names),
        "tmt_banners": len(tmt_banners),
        "status": status,
        "run_status": "NOT_RUN",
    }


def write_global_report(repo, entries):
    """Write global report files."""
    os.makedirs(JARVIS_DIR, exist_ok=True)

    total = len(entries)
    present = sum(1 for e in entries if e["status"] != "MISSING")
    missing = sum(1 for e in entries if e["status"] == "MISSING")
    hand_ported = sum(1 for e in entries if e["status"] == "HAND_PORTED")
    generated = sum(1 for e in entries if e["status"] == "GENERATED")
    stub_fail = sum(1 for e in entries if e["status"] == "STUB_FAIL")

    # Global report markdown
    report_path = os.path.join(JARVIS_DIR, "dogtag-gha-tmt-global-report.md")
    with open(report_path, "w") as fh:
        fh.write("# Dogtag GHA↔TMT Global Parity Report\n\n")
        fh.write(f"Generated for IDM-8254.\n\n")
        fh.write("## Summary\n\n")
        fh.write(f"| Metric | Count |\n")
        fh.write(f"|--------|-------|\n")
        fh.write(f"| Total GHA `*-test.yml` | {total} |\n")
        fh.write(f"| TMT present | {present} |\n")
        fh.write(f"| TMT missing | {missing} |\n")
        fh.write(f"| Hand-ported (full) | {hand_ported} |\n")
        fh.write(f"| Generated (all steps) | {generated} |\n")
        fh.write(f"| Stub-fail (has unimplemented) | {stub_fail} |\n")
        fh.write(f"| Not yet run | {total} |\n")

        fh.write("\n## By Subsystem\n\n")
        by_prefix = {}
        for e in entries:
            prefix = e["stem"].split("-")[0]
            by_prefix.setdefault(prefix, []).append(e)

        fh.write(f"| Subsystem | Total | Hand-ported | Generated | Stub-fail | Missing |\n")
        fh.write(f"|-----------|-------|-------------|-----------|-----------|--------|\n")
        for prefix in sorted(by_prefix):
            items = by_prefix[prefix]
            hp = sum(1 for e in items if e["status"] == "HAND_PORTED")
            gen = sum(1 for e in items if e["status"] == "GENERATED")
            sf = sum(1 for e in items if e["status"] == "STUB_FAIL")
            ms = sum(1 for e in items if e["status"] == "MISSING")
            fh.write(f"| {prefix} | {len(items)} | {hp} | {gen} | {sf} | {ms} |\n")

        fh.write("\n## All Tests\n\n")
        fh.write(f"| Stem | GHA Steps | TMT Banners | Status | Run |\n")
        fh.write(f"|------|-----------|-------------|--------|-----|\n")
        for e in entries:
            fh.write(f"| {e['stem']} | {e['gha_steps']} | {e['tmt_banners']} | {e['status']} | {e['run_status']} |\n")

    # Global inventory JSON
    inv_path = os.path.join(JARVIS_DIR, "dogtag-gha-tmt-global-inventory.json")
    with open(inv_path, "w") as fh:
        json.dump({
            "total_gha_workflows": total,
            "tmt_present": present,
            "tmt_missing": missing,
            "hand_ported": hand_ported,
            "generated": generated,
            "stub_fail": stub_fail,
            "entries": entries,
        }, fh, indent=2)

    print(f"Global report: {report_path}")
    print(f"Global inventory: {inv_path}")
    return report_path


def main():
    repo = find_repo_root()
    wf_dir = os.path.join(repo, WORKFLOWS_DIR)

    all_files = sorted(os.listdir(wf_dir))
    test_files = [f for f in all_files if f.endswith("-test.yml") and not is_excluded(f)]

    disabled_dir = os.path.join(wf_dir, "disabled")
    disabled_files = set()
    if os.path.isdir(disabled_dir):
        disabled_files = set(os.listdir(disabled_dir))
    test_files = [f for f in test_files if f not in disabled_files]

    only_stem = None
    for arg in sys.argv[1:]:
        only_stem = arg

    entries = []
    for f in test_files:
        stem = stem_from_filename(f)
        if only_stem and stem != only_stem:
            continue
        try:
            entry = write_stem_reports(repo, stem, f)
            entries.append(entry)
            print(f"  {entry['status']:12s} {stem}")
        except Exception as e:
            print(f"  ERROR        {stem}: {e}", file=sys.stderr)

    if not only_stem or only_stem is None:
        write_global_report(repo, entries)

    print(f"\nTotal processed: {len(entries)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
