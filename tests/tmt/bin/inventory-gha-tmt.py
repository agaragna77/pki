#!/usr/bin/env python3
"""Inventory GHA *-test.yml workflows and map to expected TMT paths.

Writes machine-readable JSON to tests/tmt/gha-tmt-inventory.json.
"""
import fnmatch
import json
import os
import sys


WORKFLOWS_DIR = ".github/workflows"
TMT_PLANS_DIR = "tests/tmt/plans"
TMT_TESTS_DIR = "tests/tmt"

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


def main():
    repo = find_repo_root()
    wf_dir = os.path.join(repo, WORKFLOWS_DIR)

    all_files = sorted(os.listdir(wf_dir))
    test_files = [f for f in all_files if f.endswith("-test.yml") and not is_excluded(f)]

    # Exclude disabled/
    disabled_dir = os.path.join(wf_dir, "disabled")
    disabled_files = set()
    if os.path.isdir(disabled_dir):
        disabled_files = set(os.listdir(disabled_dir))
    test_files = [f for f in test_files if f not in disabled_files]

    inventory = []
    for f in test_files:
        stem = stem_from_filename(f)
        plan_path = os.path.join(TMT_PLANS_DIR, f"{stem}.fmf")
        test_dir = os.path.join(TMT_TESTS_DIR, stem)
        test_sh = os.path.join(test_dir, "test.sh")
        main_fmf = os.path.join(test_dir, "main.fmf")

        plan_exists = os.path.isfile(os.path.join(repo, plan_path))
        test_dir_exists = os.path.isdir(os.path.join(repo, test_dir))
        test_sh_exists = os.path.isfile(os.path.join(repo, test_sh))
        main_fmf_exists = os.path.isfile(os.path.join(repo, main_fmf))

        inventory.append({
            "workflow": f,
            "stem": stem,
            "gha_path": os.path.join(WORKFLOWS_DIR, f),
            "tmt_plan": plan_path,
            "tmt_test_dir": test_dir,
            "tmt_test_sh": test_sh,
            "tmt_main_fmf": main_fmf,
            "plan_exists": plan_exists,
            "test_dir_exists": test_dir_exists,
            "test_sh_exists": test_sh_exists,
            "main_fmf_exists": main_fmf_exists,
            "status": "present" if (plan_exists and test_sh_exists and main_fmf_exists) else "missing",
        })

    out_path = os.path.join(repo, TMT_TESTS_DIR, "gha-tmt-inventory.json")
    with open(out_path, "w") as fh:
        json.dump({
            "total_gha_workflows": len(inventory),
            "tmt_present": sum(1 for e in inventory if e["status"] == "present"),
            "tmt_missing": sum(1 for e in inventory if e["status"] == "missing"),
            "entries": inventory,
        }, fh, indent=2)

    print(f"Wrote {out_path}")
    print(f"  Total GHA *-test.yml: {len(inventory)}")
    print(f"  TMT present: {sum(1 for e in inventory if e['status'] == 'present')}")
    print(f"  TMT missing: {sum(1 for e in inventory if e['status'] == 'missing')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
