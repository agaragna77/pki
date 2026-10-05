#!/bin/bash
# Generated TMT port of .github/workflows/ca-cert-revocation-test.yml
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
    docker volume rm ds-data 2>/dev/null || true
    docker network rm example 2>/dev/null || true
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

step "Create network"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker network create example
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create network (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=ds.example.com \
    --network=example \
    --network-alias=ds.example.com \
    --password=Secret.123 \
    ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki.example.com \
    --network=example \
    --network-alias=pki.example.com \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update CA configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set buffer size to 0 so that revocation takes effect immediately
docker exec pki pki-server ca-config-set auths.revocationChecking.bufferSize 0

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update CA configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
     ca_signing

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create test certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request uid=testuser1 | tee output

CERT1_REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" output)
echo "Cert 1 request ID: $CERT1_REQUEST_ID"

docker exec pki pki \
    -n caadmin \
    ca-cert-request-approve \
    --force \
    $CERT1_REQUEST_ID | tee output

CERT1_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" output)
echo "Cert 1 ID: $CERT1_ID"
echo "$CERT1_ID" > cert1.id

docker exec pki pki client-cert-request uid=testuser2 | tee output

CERT2_REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" output)
echo "Cert 2 request ID: $CERT2_REQUEST_ID"

docker exec pki pki \
    -n caadmin \
    ca-cert-request-approve \
    --force \
    $CERT2_REQUEST_ID | tee output

CERT2_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" output)
echo "Cert 2 ID: $CERT2_ID"
echo "$CERT2_ID" > cert2.id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create test certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert revocation using pki ca-cert commands"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT1_ID=$(cat cert1.id)
CERT2_ID=$(cat cert2.id)

# place certs on-hold
docker exec pki pki \
    -n caadmin \
    ca-cert-hold \
    --force \
    $CERT1_ID $CERT2_ID | tee output

# both certs should be revoked
echo "REVOKED" > expected
echo "REVOKED" >> expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual

# place certs off-hold
docker exec pki pki \
    -n caadmin \
    ca-cert-release-hold \
    --force \
    $CERT1_ID $CERT2_ID | tee output

# both certs should be valid
echo "VALID" > expected
echo "VALID" >> expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert revocation using pki ca-cert commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert revocation using revoker tool"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT1_ID=$(cat cert1.id)
CERT2_ID=$(cat cert2.id)

docker exec pki revoker -V

# place certs on-hold
docker exec pki revoker \
    -d /root/.dogtag/nssdb \
    -n caadmin \
    -r 6 \
    -s $CERT1_ID,$CERT2_ID \
    pki.example.com:8443 | tee output

# both certs should be revoked
echo "REVOKED" > expected
echo "REVOKED" >> expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual

# place certs off-hold
docker exec pki revoker \
    -d /root/.dogtag/nssdb \
    -n caadmin \
    -u \
    -s $CERT1_ID,$CERT2_ID \
    pki.example.com:8443 | tee output

# both certs should be valid
echo "VALID" > expected
echo "VALID" >> expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert revocation using revoker tool (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA agent cert revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-create.sh
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-create.sh
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-revoke.sh
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-unrevoke.sh
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA agent cert revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-cert-revocation-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-cert-revocation-test PASSED ===="
