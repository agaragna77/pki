#!/bin/bash
# Generated TMT port of .github/workflows/version-number-test.yml
# Step names match the GHA workflow.
set -euo pipefail

REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi

export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"
# GHA persists env vars via $GITHUB_ENV; emulate with a temp file + source.
export GITHUB_ENV="${TMPDIR:-/tmp}/gha-env-$$"
touch "$GITHUB_ENV"
source_gha_env() { set -a; source "$GITHUB_ENV" 2>/dev/null || true; set +a; }
mkdir -p "$GITHUB_WORKSPACE"
cd "$GITHUB_WORKSPACE"
export LC_ALL=C

export SHARED="/tmp/workdir/pki"


# Ensure docker and pki-runner are available
if ! command -v docker >/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

step() { echo; echo "==== $* ===="; }
GHA_FAILED=0

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: git xmlstarlet
# Most are available in the pki-runner container or Fedora host.
command -v git >/dev/null 2>&1 || dnf install -y git 2>/dev/null || true
command -v xmlstarlet >/dev/null 2>&1 || dnf install -y xmlstarlet 2>/dev/null || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Clone repository"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: actions/checkout — repo already available as $REPO_ROOT
echo "Repository available at $REPO_ROOT"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Clone repository (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get version number from RPM spec"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
MAJOR_VERSION=$(sed -n 's/^%global *major_version *\(.*\)$/\1/p' pki.spec)
echo "MAJOR_VERSION=$MAJOR_VERSION" | tee -a $GITHUB_ENV

MINOR_VERSION=$(sed -n 's/^%global *minor_version *\(.*\)$/\1/p' pki.spec)
echo "MINOR_VERSION=$MINOR_VERSION" | tee -a $GITHUB_ENV

UPDATE_VERSION=$(sed -n 's/^%global *update_version *\(.*\)$/\1/p' pki.spec)
echo "UPDATE_VERSION=$UPDATE_VERSION" | tee -a $GITHUB_ENV

VERSION=$MAJOR_VERSION.$MINOR_VERSION.$UPDATE_VERSION
echo "VERSION=$VERSION" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get version number from RPM spec (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Check version numbers in pom.xml"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo -n "$VERSION-SNAPSHOT" > expected

for filename in $(find . -name pom.xml); do
    echo "Checking version number in $filename"

    if [ "$filename" == "./pom.xml" ]; then
        xmlstarlet sel -t -v '/_:project/_:version' $filename > actual
    else
        xmlstarlet sel -t -v '/_:project/_:parent/_:version' $filename > actual
    fi

    diff expected actual
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check version numbers in pom.xml (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Setup git"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
git config --global user.name "Dr. John Doe"
git config --global user.email jdoe@example.com
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Setup git (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update to version with a phase"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
NEXT_MAJOR_VERSION=$((MAJOR_VERSION + 1))

./update_version.sh $NEXT_MAJOR_VERSION 0 0 beta1

git show

git tag --points-at HEAD  > actual
echo v$NEXT_MAJOR_VERSION.0.0-beta1 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update to version with a phase (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update to version without a phase"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
NEXT_MAJOR_VERSION=$((MAJOR_VERSION + 1))

./update_version.sh $NEXT_MAJOR_VERSION 0 0

git show

git tag --points-at HEAD  > actual
echo v$NEXT_MAJOR_VERSION.0.0 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update to version without a phase (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update to version with a phase again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
NEXT_MAJOR_VERSION=$((MAJOR_VERSION + 1))

./update_version.sh  $NEXT_MAJOR_VERSION 1 0 alpha1

git show

git tag --points-at HEAD  > actual
echo v$NEXT_MAJOR_VERSION.1.0-alpha1 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update to version with a phase again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== version-number-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== version-number-test PASSED ===="
