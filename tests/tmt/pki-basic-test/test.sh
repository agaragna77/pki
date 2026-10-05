#!/bin/bash
# Generated TMT port of .github/workflows/pki-basic-test.yml
# Step names match the GHA workflow.
set -euo pipefail

REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
BIN="$REPO_ROOT/tests/bin"

export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"
mkdir -p "$GITHUB_WORKSPACE"
cd "$GITHUB_WORKSPACE"
export LC_ALL=C

export DS_IMAGE="quay.io/389ds/dirsrv"
export SHARED="/tmp/workdir/pki"

PKI_IMAGE="${PKI_IMAGE:-pki-runner}"

# Ensure docker and pki-runner are available
if ! command -v docker >/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

cleanup() {
    docker rm -f pki 2>/dev/null || true
}
trap cleanup EXIT

step() { echo; echo "==== $* ===="; }
GHA_FAILED=0

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: xmlstarlet
# Most are available in the pki-runner container or Fedora host.
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

step "Retrieve PKI images"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: actions/cache — images built locally by prepare (build-pki-runner.sh)
echo "Images built by TMT prepare phase"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve PKI images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load PKI images"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker load from cache — images built locally by prepare
echo "Images already available (built by TMT prepare)"
docker image inspect pki-runner >/dev/null 2>&1 || { echo "ERROR: pki-runner image not found"; false; }
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Load PKI images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up runner container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki.example.com \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up runner container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki --version

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI with wrong option"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki --wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI with wrong option (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI with wrong sub-command"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ERROR: Invalid module "wrong".
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI with wrong sub-command (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI in shell mode (with prompts)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
VERSION=$(xmlstarlet sel -t -v '/_:project/_:version' pom.xml)

docker exec -i pki pki << EOF \
    > >(tee stdout) 2> >(tee stderr >&2)
nss-cert-find
nss-key-find
exit
EOF

cat > expected << EOF
PKI Command-Line Interface $VERSION
EOF

diff expected stdout

# there should be 1 prompt for each input line
cp /dev/null expected
echo -n "pki> " >> expected
echo -n "pki> " >> expected
echo -n "pki> " >> expected

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI in shell mode (with prompts) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki CLI in batch mode (without prompts)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki pki - << EOF \
    > >(tee stdout) 2> >(tee stderr >&2)
# check certs
nss-cert-find

# check keys
nss-key-find
EOF

# there should be no prompts
diff /dev/null stdout
diff /dev/null stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki CLI in batch mode (without prompts) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-basic-test PASSED ===="
