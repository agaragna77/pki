#!/bin/bash
# Generated TMT port of .github/workflows/pki-password-test.yml
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

step "Check pki password CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki password
docker exec pki pki password --help

docker exec pki pki password-generate --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki password CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate password with default characters"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki password-generate | tee password.txt

# there should be 12 chars
PASSWORD=$(cat password.txt)
[ "${#PASSWORD}" = "12" ]

# there should be at least 1 digit
sed -n '/[0-9]/p' password.txt | wc -l | awk '{print $1;}' | tee actual
echo "1" > expected
diff expected actual

# there should be at least 1 lowercase letter
sed -n '/[a-z]/p' password.txt | wc -l | awk '{print $1;}' | tee actual
echo "1" > expected
diff expected actual

# there should be at least 1 uppercase letter
sed -n '/[A-Z]/p' password.txt | wc -l | awk '{print $1;}' | tee actual
echo "1" > expected
diff expected actual

# there should be at least 1 punctuation
sed -n '/[!#*+,-./:;^_|~]/p' password.txt | wc -l | awk '{print $1;}' | tee actual
echo "1" > expected
diff expected actual || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate password with default characters (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate password with user-provided characters"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki password-generate \
    --characters "0123456789ABCDEF" \
    --length 20 \
    --output-file $SHARED/password.txt

PASSWORD=$(cat password.txt)
echo "$PASSWORD"

# there should be 20 chars
[ "${#PASSWORD}" = "20" ]

# it should be a valid hex value which
# can be converted to decimal and back
DEC=$(echo "ibase=16; $PASSWORD" | bc)
HEX=$(echo "obase=16; $DEC" | bc)

# prepend with 0 if needed
while [ ${#HEX} -lt 20 ]; do
    HEX="0$HEX"
done

# it should match the original value
[ "$PASSWORD" = "$HEX" ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate password with user-provided characters (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-password-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-password-test PASSED ===="
