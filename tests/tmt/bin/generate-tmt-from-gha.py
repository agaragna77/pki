#!/usr/bin/env python3
"""Generate TMT plan + test scaffolding from GHA *-test.yml workflows.

For each workflow the script emits:
  tests/tmt/plans/<stem>.fmf
  tests/tmt/<stem>/main.fmf
  tests/tmt/<stem>/test.sh
  tests/tmt/<stem>/README.md

Existing high-quality ports (e.g. a hand-written test.sh) are NOT overwritten
unless --force is given.
"""
import fnmatch
import json
import os
import re
import stat
import sys
import textwrap

import yaml


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

GHA_CHECKOUT_NAMES = {
    "Clone repository",
    "Clone PKI repository",
}
GHA_CACHE_NAMES = {
    "Retrieve PKI images",
    "Retrieve ACME images",
    "Retrieve IPA images",
    "Retrieve runner image",
}
GHA_LOAD_NAMES = {
    "Load PKI images",
    "Load ACME images",
    "Load IPA images",
    "Load runner image",
}
GHA_SETUP_PYTHON = {
    "Set up Python 3.9",
}

# Steps using docker/build-push-action
GHA_DOCKER_BUILD_ACTION = "docker/build-push-action"


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


def classify_step(step):
    """Return (category, detail) for a GHA step."""
    name = step.get("name", "")
    uses = step.get("uses", "")
    run = step.get("run", "")
    if_cond = step.get("if", "")

    if uses:
        action = uses.split("@")[0]
        if action == "actions/checkout":
            return "checkout", name
        if action == "actions/cache":
            return "cache", name
        if action == "actions/setup-python":
            return "setup-python", name
        if action == GHA_DOCKER_BUILD_ACTION:
            return "docker-build-action", name
        return "unknown-action", f"{name} ({action})"

    return "run", name


def strip_selinux_ls_mode_dot(text):
    """Normalize ``ls -l`` mode bits so SELinux-capable hosts match GHA goldens.

    On SELinux hosts, coreutils ``ls -l`` prints a trailing ``.`` after the mode
    (e.g. ``lrwxrwxrwx.``). GHA expected listings omit it; without stripping,
    ``diff`` fails on libvirt/Fedora guests even when layout/owners match.
    """
    marker = r"-e 's/^\(\S*\)\./\1/'"
    if marker in text:
        return text
    # Insert after the usual `/^total/d` sed expression used by PKI dir checks.
    pattern = (
        r"(-e '/\^total/d' \\)" + "\n"
        + r"([ \t]*)(-e 's/\^\\\(\\S\*\\\))"
    )

    def _insert(match):
        return (
            match.group(1)
            + "\n"
            + match.group(2)
            + marker
            + " \\\n"
            + match.group(2)
            + match.group(3)
        )

    return re.sub(pattern, _insert, text)


def neutralize_grep_wc_pipefail(text):
    """Make ``grep | wc -l`` safe under ``set -o pipefail``.

    ``grep`` exits 1 when there are no matches. That is often the success case
    (e.g. count orphans == 0), but pipefail turns it into a step failure.
    """
    return re.sub(
        r"^([ \t]*)grep (.+) \| wc -l( > \S+)\s*$",
        r"\1{ grep \2 || true; } | wc -l\3",
        text,
        flags=re.M,
    )


def translate_gha_expr(text):
    """Crude translation of GHA expression syntax to shell."""
    text = text.replace("${{ github.workspace }}", "${GITHUB_WORKSPACE}")
    text = text.replace("$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}")
    text = re.sub(r"\$\{\{\s*env\.(\w+)\s*\}\}", r"${\1}", text)
    text = re.sub(r"\$\{\{\s*vars\.DS_IMAGE\s*\|\|\s*'([^']+)'\s*\}\}", r"\1", text)
    text = re.sub(r"\$\{\{\s*vars\.\w+\s*\|\|\s*'([^']+)'\s*\}\}", r"\1", text)
    text = re.sub(r"\$\{\{\s*github\.sha\s*\}\}", "local", text)
    text = text.replace("${{ matrix.", "${MATRIX_")
    text = re.sub(r"\$\{\{[^}]*\}\}", '"# GHA-EXPR"', text)
    text = strip_selinux_ls_mode_dot(text)
    text = neutralize_grep_wc_pipefail(text)
    return text


def translate_if_cond(if_cond):
    """Turn GHA if: into a shell condition or None (skip wrapping)."""
    if not if_cond:
        return None
    stripped = if_cond.strip()
    if stripped == "always()":
        return None  # always run (see emit_guarded_step)
    if stripped == "failure()":
        return '[[ "$GHA_FAILED" -ne 0 ]]'
    if stripped == "success()":
        return '[[ "$GHA_FAILED" -eq 0 ]]'
    m = re.match(r"\$\{\{\s*fromJSON\(env\.(\w+)\)\s*(<|>|<=|>=|==|!=)\s*(\d+)\s*\}\}", stripped)
    if m:
        var, op, val = m.groups()
        opmap = {
            "<": "-lt",
            ">": "-gt",
            "<=": "-le",
            ">=": "-ge",
            "==": "-eq",
            "!=": "-ne",
        }
        return f'[[ "${{{var}}}" {opmap[op]} {val} ]]'
    return None


def gha_step_guard(if_cond):
    """Shell guard so later steps emulate GHA success/always/failure semantics.

    With ``set -e``, a failed step would otherwise skip ``if: always()`` log/assert
    steps. Track ``GHA_FAILED`` and still run always() bodies (they may fail).
    """
    stripped = (if_cond or "").strip()
    extra = translate_if_cond(if_cond)
    if stripped == "always()":
        return None, extra, "always"
    if stripped == "failure()":
        return extra, extra, "failure"
    if extra:
        return f'[[ "$GHA_FAILED" -eq 0 ]] && {extra}', extra, "cond"
    return '[[ "$GHA_FAILED" -eq 0 ]]', extra, "success"


def emit_guarded_step(lines, name, body_lines, if_cond="", extra_after=None):
    """Emit a step that records failure without aborting always() follow-ups.

    Body is an unindented subshell so GHA heredocs stay valid and ``set -e``
    inside the subshell does not exit the whole test.
    """
    lines.append(f'step "{sanitize_step_name(name)}"')
    stripped = (if_cond or "").strip()
    if stripped == "always()":
        lines.append("# GHA if: always() — run even after prior step failures; may fail the test")
    elif stripped == "failure()":
        lines.append("# GHA if: failure() — run only if a prior step failed")

    guard, _, _kind = gha_step_guard(if_cond)
    if guard:
        lines.append(f"if {guard}; then")

    lines.append("set +e")
    lines.append("(")
    lines.append("set -euo pipefail")
    for bl in body_lines:
        lines.append(bl)
    lines.append(")")
    lines.append("_rc=$?")
    lines.append("set -euo pipefail")
    lines.append("if [[ $_rc -ne 0 ]]; then")
    lines.append(f'    echo "FAIL: {sanitize_step_name(name)} (rc=$_rc)" >&2')
    lines.append("    GHA_FAILED=$_rc")
    lines.append("fi")
    if extra_after:
        for el in extra_after:
            lines.append(el)
    if guard:
        lines.append("fi")
    lines.append("")


def sanitize_step_name(name):
    """Make a step name safe for shell banner."""
    return name.replace('"', '\\"')


def generate_test_sh(stem, workflow_name, steps, env_vars):
    """Generate test.sh content from GHA steps."""
    lines = [
        "#!/bin/bash",
        f"# Generated TMT port of .github/workflows/{stem}.yml",
        "# Step names match the GHA workflow.",
        "set -euo pipefail",
        "",
        'REPO_ROOT="${TMT_TREE:-}"',
        'if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then',
        '    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)',
        "fi",
    ]

    has_tests_bin = any(
        "tests/bin/" in (s.get("run", "") or "")
        for s in steps
        if s.get("run")
    )
    if has_tests_bin:
        lines.append('BIN="$REPO_ROOT/tests/bin"')

    # Check if workflow uses GITHUB_ENV
    uses_github_env = any(
        "GITHUB_ENV" in (s.get("run", "") or "")
        for s in steps
    )

    lines.extend([
        "",
        'export GITHUB_WORKSPACE="$REPO_ROOT"',
        'export SHARED="${SHARED:-/tmp/workdir/pki}"',
    ])

    if uses_github_env:
        lines.extend([
            '# GHA persists env vars via $GITHUB_ENV; emulate with a temp file + source.',
            'export GITHUB_ENV="${TMPDIR:-/tmp}/gha-env-$$"',
            'touch "$GITHUB_ENV"',
            'source_gha_env() { set -a; source "$GITHUB_ENV" 2>/dev/null || true; set +a; }',
        ])

    lines.extend([
        'mkdir -p "$GITHUB_WORKSPACE"',
        'cd "$GITHUB_WORKSPACE"',
        # Match GHA/ubuntu byte-order sort for golden ``diff`` listings.
        'export LC_ALL=C',
        "",
    ])

    # Env vars from the workflow
    for k, v in env_vars.items():
        val = translate_gha_expr(str(v))
        lines.append(f'export {k}="{val}"')
    if env_vars:
        lines.append("")

    # Docker image variables
    ds_image_used = any("DS_IMAGE" in (s.get("run", "") or "") for s in steps)
    if ds_image_used and "DS_IMAGE" not in env_vars:
        lines.append('DS_IMAGE="${DS_IMAGE:-quay.io/389ds/dirsrv}"')

    pki_image_used = any(
        "pki-runner" in (s.get("run", "") or "").lower() or
        "runner-init.sh" in (s.get("run", "") or "")
        for s in steps
    )
    if pki_image_used:
        lines.append('PKI_IMAGE="${PKI_IMAGE:-pki-runner}"')

    lines.extend([
        "",
        "# Ensure docker and pki-runner are available",
        'if ! command -v docker >/dev/null; then',
        '    echo "ERROR: docker not found" >&2',
        '    exit 1',
        'fi',
    ])

    # Determine which containers are used for cleanup
    containers = set()
    for s in steps:
        run = s.get("run", "") or ""
        for m in re.finditer(r"docker\s+(?:exec|rm|stop)\s+(?:-[fi]\s+)*(\w+)", run):
            c = m.group(1)
            if c not in ("--force", "-f"):
                containers.add(c)
    # Also check runner-init.sh calls
    for s in steps:
        run = s.get("run", "") or ""
        for m in re.finditer(r"runner-init\.sh\b.*?(\w+)\s*$", run, re.MULTILINE):
            containers.add(m.group(1))

    uses_network = any("docker network create" in (s.get("run", "") or "") for s in steps)
    uses_volume = any("docker volume" in (s.get("run", "") or "") for s in steps)
    # ds-create.sh does `docker volume create $NAME-data` outside the workflow text,
    # so volume teardown must be inferred for shared-guest multi-test plans.
    uses_ds_create = any("ds-create.sh" in (s.get("run", "") or "") for s in steps)

    if containers or uses_network or uses_volume or uses_ds_create:
        lines.append("")
        lines.append("cleanup() {")
        if containers:
            clist = " ".join(sorted(containers))
            lines.append(f"    docker rm -f {clist} 2>/dev/null || true")
        vol_names = set()
        for s in steps:
            run = s.get("run", "") or ""
            for m in re.finditer(r"docker\s+volume\s+(?:create|rm)\s+(\S+)", run):
                vol_names.add(m.group(1))
            if "ds-create.sh" in run:
                # Final bare word is the container name → volume is <name>-data.
                bare = re.findall(r"(?m)^([A-Za-z][\w-]*)\s*$", run)
                for name in bare:
                    if name.startswith("-"):
                        continue
                    vol_names.add(f"{name}-data")
                vol_names.add("ds-data")
        if "ds" in containers:
            vol_names.add("ds-data")
        if vol_names:
            vlist = " ".join(sorted(vol_names))
            lines.append(f"    docker volume rm {vlist} 2>/dev/null || true")
        if uses_network:
            net_names = set()
            for s in steps:
                run = s.get("run", "") or ""
                for m in re.finditer(r"docker\s+network\s+(?:create|rm)\s+(\S+)", run):
                    net_names.add(m.group(1))
            for net in sorted(net_names):
                lines.append(f"    docker network rm {net} 2>/dev/null || true")
        lines.append("}")
        lines.append("trap cleanup EXIT")

    lines.extend([
        "",
        'step() { echo; echo "==== $* ===="; }',
        "GHA_FAILED=0",
        "",
    ])

    # Now emit translated steps
    for s in steps:
        cat, detail = classify_step(s)
        name = s.get("name", "")
        run = s.get("run", "") or ""
        if_cond = s.get("if", "")

        extra_after = []
        if uses_github_env and "GITHUB_ENV" in run:
            extra_after = ["source_gha_env"]

        if cat == "checkout":
            emit_guarded_step(
                lines, name,
                [
                    "# GHA: actions/checkout — repo already available as $REPO_ROOT",
                    'echo "Repository available at $REPO_ROOT"',
                ],
                if_cond,
            )
            continue

        if cat == "cache":
            emit_guarded_step(
                lines, name,
                [
                    "# GHA: actions/cache — images built locally by prepare (build-pki-runner.sh)",
                    'echo "Images built by TMT prepare phase"',
                ],
                if_cond,
            )
            continue

        if cat == "setup-python":
            emit_guarded_step(
                lines, name,
                [
                    "# GHA: actions/setup-python — using system python3",
                    "python3 --version",
                ],
                if_cond,
            )
            continue

        if cat == "docker-build-action":
            with_block = s.get("with", {})
            context = with_block.get("context", ".")
            file_path = with_block.get("file", "")
            tags = with_block.get("tags", "")
            build_args = with_block.get("build-args", "")
            build_cmd = "docker build"
            if file_path:
                build_cmd += f" -f {translate_gha_expr(file_path)}"
            if tags:
                for tag in str(tags).strip().split("\n"):
                    tag = tag.strip()
                    if tag:
                        build_cmd += f" -t {translate_gha_expr(tag)}"
            if build_args:
                for arg in str(build_args).strip().split("\n"):
                    arg = arg.strip()
                    if arg:
                        build_cmd += f' --build-arg "{translate_gha_expr(arg)}"'
            build_cmd += f" {translate_gha_expr(context)}"
            emit_guarded_step(
                lines, name,
                [
                    "# GHA: docker/build-push-action — translated to docker build",
                    build_cmd,
                ],
                if_cond,
            )
            continue

        if cat == "unknown-action":
            action = s.get("uses", "").split("@")[0]
            emit_guarded_step(
                lines, name,
                [
                    f'echo "FAIL: unimplemented GHA step: {name} (action: {action})"',
                    "false",
                ],
                if_cond,
            )
            continue

        # cat == "run"
        # Handle Load PKI/ACME/IPA images (docker load)
        if name in GHA_LOAD_NAMES:
            body = [
                "# GHA: docker load from cache — images built locally by prepare",
                'echo "Images already available (built by TMT prepare)"',
            ]
            if "pki" in name.lower() or "runner" in name.lower():
                body.append(
                    'docker image inspect pki-runner >/dev/null 2>&1 '
                    '|| { echo "ERROR: pki-runner image not found"; false; }'
                )
            emit_guarded_step(lines, name, body, if_cond)
            continue

        # Handle Install dependencies (apt-get)
        if name == "Install dependencies" and "apt-get" in run:
            body = [
                "# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf",
            ]
            pkgs = set()
            for m in re.finditer(r"apt-get\s+(?:-y\s+)?install\s+(.*)", run):
                for p in m.group(1).split():
                    if not p.startswith("-"):
                        pkgs.add(p)
            if pkgs:
                body.append(f"# Packages needed: {' '.join(sorted(pkgs))}")
                body.append("# Most are available in the pki-runner container or Fedora host.")
                for pkg in sorted(pkgs):
                    body.append(
                        f"command -v {pkg} >/dev/null 2>&1 || dnf install -y {pkg} 2>/dev/null || true"
                    )
            emit_guarded_step(lines, name, body, if_cond)
            continue

        translated = translate_gha_expr(run.rstrip())
        body_lines = translated.split("\n")
        # Known flake: CASystemCertCheck audit_signing NSS "Request timed out".
        # Retry hard (still fail if all attempts fail) — no soft-continue.
        if "pki-healthcheck" in run and "healthcheck" in name.lower():
            indented = "\n".join(
                ("    " + bl) if bl.strip() else bl for bl in body_lines
            )
            body_lines = [
                "# Retry pki-healthcheck: intermittent NSS load timeout on audit_signing",
                "hc_ok=0",
                "for hc_try in 1 2 3; do",
                '    echo "pki-healthcheck attempt ${hc_try}/3"',
                "    if (",
                "    set -euo pipefail",
                indented,
                "    ); then",
                "        hc_ok=1",
                "        break",
                "    fi",
                '    sleep 5',
                "done",
                '[[ "$hc_ok" -eq 1 ]]',
            ]
        emit_guarded_step(
            lines, name, body_lines, if_cond, extra_after=extra_after
        )

    lines.extend([
        'if [[ "$GHA_FAILED" -ne 0 ]]; then',
        f'    echo "==== {stem} FAILED ===="',
        '    exit "$GHA_FAILED"',
        "fi",
        f'echo "==== {stem} PASSED ===="',
    ])
    return "\n".join(lines) + "\n"


def generate_plan_fmf(stem, workflow_name):
    """Generate the .fmf plan file."""
    # Determine subsystem tag from stem prefix
    tags = ["dogtag", "idm-8254"]
    prefix = stem.split("-")[0]
    if prefix in ("ca", "kra", "ocsp", "tks", "tps", "acme", "est", "scep", "lwca", "subca"):
        tags.insert(0, prefix)
    elif prefix in ("pki", "server", "java", "python"):
        tags.insert(0, prefix)
    elif prefix in ("ipa",):
        tags.insert(0, "ipa")

    lines = [
        f"summary: {workflow_name}",
        "description: |",
        f"  TMT port of .github/workflows/{stem}.yml.",
        "  Prepare builds pki-runner from the Dockerfile (same as GHA).",
        f"  See tests/tmt/{stem}/README.md",
        "discover:",
        "    how: fmf",
        "    test:",
        f"        - /tests/tmt/{stem}",
        "provision:",
        "    how: local",
        "prepare:",
        "    - name: require-docker",
        "      how: shell",
        "      script:",
        "        - |",
        "          command -v docker >/dev/null \\",
        f'            || {{ echo "ERROR: docker required for {stem}"; exit 1; }}',
        "    - name: build-pki-runner",
        "      how: shell",
        "      script:",
        "        - |",
        f'          "${{TMT_TREE}}/tests/tmt/bin/build-pki-runner.sh" "${{TMT_TREE}}"',
        "execute:",
        "    how: tmt",
        "finish:",
        "    how: shell",
        "    script:",
        "      - |",
        "        docker rm -f pki ds 2>/dev/null || true",
        "        docker volume rm ds-data 2>/dev/null || true",
        "        docker network rm example 2>/dev/null || true",
        "tag:",
    ]
    for t in tags:
        lines.append(f"    - {t}")
    lines.extend([
        "link:",
        "    - verifies: https://redhat.atlassian.net/browse/IDM-8254",
        f"    - relates: https://github.com/dogtagpki/pki/blob/master/.github/workflows/{stem}.yml",
    ])
    return "\n".join(lines) + "\n"


def generate_main_fmf(stem, workflow_name):
    """Generate the main.fmf test metadata."""
    prefix = stem.split("-")[0]
    tags = []
    if prefix in ("ca", "kra", "ocsp", "tks", "tps", "acme", "est", "scep", "lwca", "subca"):
        tags.append(prefix)
    elif prefix in ("pki", "server", "java", "python", "ipa"):
        tags.append(prefix)
    tags.extend(["dogtag", "idm-8254"])

    lines = [
        f"summary: {workflow_name} (GHA {stem})",
        "description: |",
        f"  TMT port of .github/workflows/{stem}.yml.",
        "test: ./test.sh",
        "framework: shell",
        "require: []",
        "duration: 180m" if stem == "ca-basic-test" else "duration: 60m",
        "tag:",
    ]
    for t in tags:
        lines.append(f"    - {t}")
    lines.extend([
        "link:",
        "    - verifies: https://redhat.atlassian.net/browse/IDM-8254",
        f"    - implements: /.github/workflows/{stem}.yml",
    ])
    return "\n".join(lines) + "\n"


def generate_readme(stem, workflow_name, step_names):
    """Generate a README.md for the test directory."""
    step_list = "\n".join(f"- {n}" for n in step_names)
    return textwrap.dedent(f"""\
        # {workflow_name}

        TMT port of `.github/workflows/{stem}.yml`.

        ## Steps

        {step_list}

        ## Usage

            tmt run plan --name {stem}

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
    """)


def process_workflow(repo, filename, force=False):
    """Process a single workflow file, generating TMT plan + test."""
    stem = stem_from_filename(filename)
    wf_path = os.path.join(repo, WORKFLOWS_DIR, filename)

    with open(wf_path) as fh:
        data = yaml.safe_load(fh)

    workflow_name = data.get("name", stem)

    # Find the primary test job
    jobs = data.get("jobs", {})
    job_name = None
    job_data = None
    for jn in ("test", "Test"):
        if jn in jobs:
            job_name = jn
            job_data = jobs[jn]
            break
    if job_data is None:
        # Take the first job
        job_name = next(iter(jobs))
        job_data = jobs[job_name]

    steps = job_data.get("steps", [])
    step_names = [s.get("name", "<unnamed>") for s in steps]

    # Collect env vars from workflow level and job level
    env_vars = {}
    for k, v in data.get("env", {}).items():
        env_vars[k] = v
    for k, v in job_data.get("env", {}).items():
        env_vars[k] = v

    # Paths
    plan_dir = os.path.join(repo, TMT_PLANS_DIR)
    test_dir = os.path.join(repo, TMT_TESTS_DIR, stem)
    plan_path = os.path.join(plan_dir, f"{stem}.fmf")
    test_sh_path = os.path.join(test_dir, "test.sh")
    main_fmf_path = os.path.join(test_dir, "main.fmf")
    readme_path = os.path.join(test_dir, "README.md")

    # Keep existing tests unless --force (including former hand-ports).
    if os.path.isfile(test_sh_path) and not force:
        return stem, "kept", step_names

    os.makedirs(plan_dir, exist_ok=True)
    os.makedirs(test_dir, exist_ok=True)

    # Generate plan (skip if exists and not forced)
    if not os.path.isfile(plan_path) or force:
        with open(plan_path, "w") as fh:
            fh.write(generate_plan_fmf(stem, workflow_name))

    # Generate test.sh
    with open(test_sh_path, "w") as fh:
        fh.write(generate_test_sh(stem, workflow_name, steps, env_vars))
    os.chmod(test_sh_path, os.stat(test_sh_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Generate main.fmf
    with open(main_fmf_path, "w") as fh:
        fh.write(generate_main_fmf(stem, workflow_name))

    # Generate README
    with open(readme_path, "w") as fh:
        fh.write(generate_readme(stem, workflow_name, step_names))

    return stem, "generated", step_names


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

    force = "--force" in sys.argv
    only_stem = None
    for arg in sys.argv[1:]:
        if arg != "--force":
            only_stem = arg

    generated = 0
    kept = 0
    results = []

    for f in test_files:
        stem = stem_from_filename(f)
        if only_stem and stem != only_stem:
            continue
        try:
            s, status, step_names = process_workflow(repo, f, force=force)
            results.append((s, status, len(step_names)))
            if status == "generated":
                generated += 1
            else:
                kept += 1
            print(f"  {status:10s} {s} ({len(step_names)} steps)")
        except Exception as e:
            print(f"  ERROR      {stem}: {e}", file=sys.stderr)
            results.append((stem, "error", 0))

    print(f"\nTotal: {len(results)}  Generated: {generated}  Kept: {kept}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
