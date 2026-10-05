#!/bin/bash
# Generated TMT port of .github/workflows/ca-mldsa-CRMFPopClient-test.yml
# Step names match the GHA workflow.
set -euo pipefail

REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
BIN="$REPO_ROOT/tests/bin"

export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"
# GHA persists env vars via $GITHUB_ENV; emulate with a temp file + source.
export GITHUB_ENV="${TMPDIR:-/tmp}/gha-env-$$"
touch "$GITHUB_ENV"
source_gha_env() { set -a; source "$GITHUB_ENV" 2>/dev/null || true; set +a; }
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

docker exec pki dnf install -y dumpasn1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec pki sed -n 's/^VERSION_ID=//p' /etc/os-release)
echo "FEDORA_VERSION=$FEDORA_VERSION" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Fedora version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Enable ML-DSA in default crypto-policies"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec pki sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies (rc=$_rc)" >&2
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

step "Set up CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable caMLDSAUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-profile-enable caMLDSAUserCert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable caMLDSAUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll ML-DSA cert using CRMFPopClient without POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate ML-DSA CRMF request
# Note: -t false is NOT specified, relying on default for mldsa
docker exec pki CRMFPopClient \
    -d /root/.dogtag/nssdb \
    -p "" \
    -a mldsa \
    -l 65 \
    -n "cn=Test User,uid=testuser,ou=users" \
    -q POP_NONE \
    -o test-ML-DSA-CRMFPopClient.csr \
    -v

docker exec pki cat test-ML-DSA-CRMFPopClient.csr

docker exec pki AtoB test-ML-DSA-CRMFPopClient.csr test-ML-DSA-CRMFPopClient.der
docker exec pki dumpasn1 test-ML-DSA-CRMFPopClient.der

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caMLDSAUserCert \
    --subject "cn=Test User,uid=testuser,ou=users" \
    --csr-file test-ML-DSA-CRMFPopClient.csr \
    --output-file test-ML-DSA-CRMFPopClient.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-ML-DSA-CRMFPopClient.crt \
    testuser

docker exec pki pki nss-cert-show testuser | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: testuser
  Subject DN: UID=testuser,CN=Test User,OU=users
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll ML-DSA cert using CRMFPopClient without POP (rc=$_rc)" >&2
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
    echo "==== ca-mldsa-CRMFPopClient-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-mldsa-CRMFPopClient-test PASSED ===="
