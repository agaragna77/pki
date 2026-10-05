#!/bin/bash
# Generated TMT port of .github/workflows/pki-pkcs11-test.yml
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

step "Check pki pkcs11 CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs11
docker exec pki pki pkcs11 --help

docker exec pki pki pkcs11-cert-export --help
docker exec pki pki pkcs11-cert-find --help
docker exec pki pki pkcs11-cert-show --help
docker exec pki pki pkcs11-cert-del --help

docker exec pki pki pkcs11-key-find --help
docker exec pki pki pkcs11-key-show --help
docker exec pki pki pkcs11-key-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki pkcs11 CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create HSM token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y softhsm
docker exec pki softhsm2-util --init-token \
    --label HSM \
    --so-pin Secret.HSM \
    --pin Secret.HSM \
    --free
docker exec pki softhsm2-util --show-slots
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create HSM token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "CN=Certificate 1" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr cert1.csr
docker exec pki pki nss-cert-issue \
    --csr cert1.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert cert1.crt

docker exec pki pki nss-cert-import \
    --cert cert1.crt \
    --trust CT,C,C \
    cert1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "internal=" > password.conf
echo "hardware-HSM=Secret.HSM" >> password.conf

docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    nss-cert-request \
    --subject "CN=Certificate 2" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr cert2.csr
docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    nss-cert-issue \
    --csr cert2.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert cert2.crt
docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert cert2.crt \
    --trust CT,C,C \
    cert2
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify certs creation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# internal token should have cert1 and cert2
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
cat output | sed -n 's/^\s*\(\S\+\)\s\+\S\+\s*$/\1/p' > expected

docker exec pki pki pkcs11-cert-find | tee output
sed -n 's/^\s*Cert ID:\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected

docker exec pki pki pkcs11-cert-show cert1
docker exec pki pki pkcs11-cert-export cert1

docker exec pki pki pkcs11-cert-show cert2
docker exec pki pki pkcs11-cert-export cert2

# HSM should have cert2 only
echo "Secret.HSM" > password.txt
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -h HSM \
    -f $SHARED/password.txt | tee output
sed -n 's/^\s*\(\S\+\)\s\+\S\+\s*$/\1/p' output > expected

docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-cert-find | tee output
sed -n 's/^\s*Cert ID:\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected

docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-cert-show \
    HSM:cert2
docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-cert-export \
    HSM:cert2
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify certs creation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify cert keys creation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# internal token should have cert1's key
docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^\s*<.\+>\s\+\S\+\s\+\(\S\+\)\s\+.*$/\1/p' output > cert1key

docker exec pki pki pkcs11-key-find | tee output
sed -n 's/^\s*Key ID:\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual cert1key

docker exec pki pki pkcs11-key-show `cat cert1key`

# HSM should have cert2's key
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -h HSM \
    -f $SHARED/password.txt | tee output
sed -n 's/^\s*<.\+>\s\+\S\+\s\+\(\S\+\)\s\+.*$/\1/p' output > cert2key

docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-key-find | tee output
sed -n 's/^\s*Key ID:\s*HSM:\(\S\+\)\s*$/\1/p' output > actual
diff actual cert2key

docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-key-show \
    HSM:`cat cert2key`
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify cert keys creation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs11-cert-del cert1
docker exec pki pki pkcs11-cert-del cert2
docker exec pki pki --token HSM -f $SHARED/password.conf pkcs11-cert-del HSM:cert2
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove cert keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs11-key-del `cat cert1key`
docker exec pki pki \
    --token HSM \
    -f $SHARED/password.conf \
    pkcs11-key-del \
    HSM:`cat cert2key`
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove cert keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify certs removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# internal token should have no certs
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^\s*\(\S\+\)\s\+\S\+\s*$/\1/p' output > actual
diff actual /dev/null

# HSM should have no certs
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -h HSM \
    -f $SHARED/password.txt | tee output
sed -n 's/^\s*\(\S\+\)\s\+\S\+\s*$/\1/p' output > actual
diff actual /dev/null
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify certs removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify cert keys removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# internal token should have no cert keys
docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^\s*<.\+>\s\+\S\+\s\+\(\S\+\)\s\+.*$/\1/p' output > actual
diff actual /dev/null

# HSM should have no cert keys
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -h HSM \
    -f $SHARED/password.txt | tee output
sed -n 's/^\s*<.\+>\s\+\S\+\s\+\(\S\+\)\s\+.*$/\1/p' output > actual
diff actual /dev/null
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify cert keys removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove HSM token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki softhsm2-util --delete-token --token HSM
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove HSM token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-pkcs11-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-pkcs11-test PASSED ===="
