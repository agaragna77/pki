#!/bin/bash
# Generated TMT port of .github/workflows/pki-pkcs12-test.yml
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

step "Check pki pkcs12 CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12
docker exec pki pki pkcs12 --help

docker exec pki pki pkcs12-export --help
docker exec pki pki pkcs12-import --help

docker exec pki pki pkcs12-cert-export --help
docker exec pki pki pkcs12-cert-import --help
docker exec pki pki pkcs12-cert-find --help
docker exec pki pki pkcs12-cert-mod --help
docker exec pki pki pkcs12-cert-del --help

docker exec pki pki pkcs12-key-find --help
docker exec pki pki pkcs12-key-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki pkcs12 CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki pki - << EOF
nss-key-create \
    --key-id-file $SHARED/ca_signing.key_id
nss-cert-request \
    --key-id-file $SHARED/ca_signing.key_id \
    --subject "CN=Certificate Authority" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/ca_signing.csr
nss-cert-issue \
    --csr $SHARED/ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert $SHARED/ca_signing.crt
nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing
EOF

cat ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki pki - << EOF
nss-key-create \
    --key-id-file $SHARED/sslserver.key_id
nss-cert-request \
    --key-id-file $SHARED/sslserver.key_id \
    --subject "CN=localhost.localdomain" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/sslserver.csr
nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/sslserver.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert $SHARED/sslserver.crt
nss-cert-import \
    --cert $SHARED/sslserver.crt \
    sslserver
EOF

cat sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki pki - << EOF
nss-key-create \
    --key-id-file $SHARED/audit_signing.key_id
nss-cert-request \
    --key-id-file $SHARED/audit_signing.key_id \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --csr $SHARED/audit_signing.csr
nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/audit_signing.csr \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --cert $SHARED/audit_signing.crt
nss-cert-import \
    --cert $SHARED/audit_signing.crt \
    --trust ,,P \
    audit_signing
EOF

cat audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs and keys in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^\(\S\+\)\s*\(\S\+\)\s*$/\1 \2/p' output > actual

# all certs should be be present with trust flags
cat > expected << EOF
ca_signing CTu,Cu,Cu
sslserver u,u,u
audit_signing u,u,Pu
EOF

diff expected actual

docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+.*:\(\S\+\)/\2 0x\1/p' output > actual

# CA signing key should not be present
cat > expected << EOF
ca_signing $(cat ca_signing.key_id)
sslserver $(cat sslserver.key_id)
audit_signing $(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs and keys in NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export everything into PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-export \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export everything into PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs and keys in PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-cert-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n \
    -e '/^\s*Friendly Name:/p' \
    -e '/^\s*Trust Flags:/p' \
    -e '/^\s*Has Key:/p' \
    -e '/^$/p' \
    output > actual

# all certs should be present
cat > expected << EOF
  Friendly Name: ca_signing
  Trust Flags: CTu,Cu,Cu
  Has Key: true

  Friendly Name: sslserver
  Trust Flags: u,u,u
  Has Key: true

  Friendly Name: audit_signing
  Trust Flags: u,u,Pu
  Has Key: true
EOF

diff expected actual

docker exec pki pki pkcs12-key-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n 's/^\s*Key ID:\s*\(.\+\)\s*$/\1/p' output > actual

# all keys should be present
cat > expected << EOF
$(cat ca_signing.key_id)
$(cat sslserver.key_id)
$(cat audit_signing.key_id)
EOF

diff expected actual

docker exec pki pki pkcs12-cert-export \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    --cert-file $SHARED/ca_signing2.crt \
    ca_signing

# CA signing cert should match the original
diff ca_signing.crt ca_signing2.crt

docker exec pki pki pkcs12-cert-export \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    --cert-file $SHARED/sslserver2.crt \
    sslserver

# SSL server cert should match the original
diff sslserver.crt sslserver2.crt

docker exec pki pki pkcs12-cert-export \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    --cert-file $SHARED/audit_signing2.crt \
    audit_signing

# audit signing cert should match the original
diff audit_signing.crt audit_signing2.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs and keys in PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA signing key from PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-key-del \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    $(cat ca_signing.key_id)

docker exec pki pki pkcs12-cert-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n \
    -e '/^\s*Friendly Name:/p' \
    -e '/^\s*Trust Flags:/p' \
    -e '/^\s*Has Key:/p' \
    -e '/^$/p' \
    output > actual

# all certs should be present
cat > expected << EOF
  Friendly Name: ca_signing
  Trust Flags: CT,C,C
  Has Key: false

  Friendly Name: sslserver
  Trust Flags: u,u,u
  Has Key: true

  Friendly Name: audit_signing
  Trust Flags: u,u,Pu
  Has Key: true
EOF

diff expected actual

docker exec pki pki pkcs12-key-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n 's/^\s*Key ID:\s*\(.\+\)\s*$/\1/p' output > actual

# CA signing key should be removed
cat > expected << EOF
$(cat sslserver.key_id)
$(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA signing key from PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove audit signing cert and key from PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-cert-del \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    audit_signing

docker exec pki pki pkcs12-cert-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n \
    -e '/^\s*Friendly Name:/p' \
    -e '/^\s*Trust Flags:/p' \
    -e '/^\s*Has Key:/p' \
    -e '/^$/p' \
    output > actual

# audit signing cert should be removed
cat > expected << EOF
  Friendly Name: ca_signing
  Trust Flags: CT,C,C
  Has Key: false

  Friendly Name: sslserver
  Trust Flags: u,u,u
  Has Key: true
EOF

diff expected actual

docker exec pki pki pkcs12-key-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n 's/^\s*Key ID:\s*\(.\+\)\s*$/\1/p' output > actual

# audit signing key should be removed
cat > expected << EOF
$(cat sslserver.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove audit signing cert and key from PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Re-import audit signing cert and key into PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-cert-import \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 \
    --append \
    --no-chain \
    audit_signing

docker exec pki pki pkcs12-cert-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n \
    -e '/^\s*Friendly Name:/p' \
    -e '/^\s*Trust Flags:/p' \
    -e '/^\s*Has Key:/p' \
    -e '/^$/p' \
    output > actual

# audit signing cert should be imported
cat > expected << EOF
  Friendly Name: ca_signing
  Trust Flags: CT,C,C
  Has Key: false

  Friendly Name: sslserver
  Trust Flags: u,u,u
  Has Key: true

  Friendly Name: audit_signing
  Trust Flags: u,u,Pu
  Has Key: true
EOF

diff expected actual

docker exec pki pki pkcs12-key-find \
    --pkcs12-file test.p12 \
    --pkcs12-password Secret.123 | tee output
sed -n 's/^\s*Key ID:\s*\(.\+\)\s*$/\1/p' output > actual

# audit signing key should be imported
cat > expected << EOF
$(cat sslserver.key_id)
$(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Re-import audit signing cert and key into PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import everything from PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -d nssdb1 pkcs12-import \
    --pkcs12 test.p12 \
    --password Secret.123

docker exec pki certutil -L -d nssdb1 | tee output
sed -n 's/^\(\S\+\)\s*\(\S\+\)\s*$/\1 \2/p' output > actual

# all certs should be be present with trust flags
cat > expected << EOF
ca_signing CT,C,C
sslserver u,u,u
audit_signing u,u,Pu
EOF

diff expected actual

docker exec pki certutil -K -d nssdb1 | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+\(\S\+\)/\2 0x\1/p' output > actual

# CA signing key should not be present
cat > expected << EOF
sslserver $(cat sslserver.key_id)
audit_signing $(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import everything from PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import PKCS #12 file without trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -d nssdb2 pkcs12-import \
    --pkcs12 test.p12 \
    --password Secret.123 \
    --no-trust-flags

docker exec pki certutil -L -d nssdb2 | tail -n +5 | tee output
sed -n 's/^\(\S\+\)\s*\(\S\+\)\s*$/\1 \2/p' output > actual

# all certs should be present without trust flags
cat > expected << EOF
ca_signing ,,
sslserver u,u,u
audit_signing u,u,u
EOF

diff expected actual

docker exec pki certutil -K -d nssdb2 | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+\(\S\+\)/\2 0x\1/p' output > actual

# CA signing key should not be present
cat > expected << EOF
sslserver $(cat sslserver.key_id)
audit_signing $(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import PKCS #12 file without trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import PKCS #12 file without CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -d nssdb3 pkcs12-import \
    --pkcs12 test.p12 \
    --password Secret.123 \
    --no-ca-certs

docker exec pki certutil -L -d nssdb3 | tail -n +5 | tee output
sed -n 's/^\(\S\+\)\s*\(\S\+\)\s*$/\1 \2/p' output > actual

# CA signing cert should not be present
cat > expected << EOF
sslserver u,u,u
audit_signing u,u,Pu
EOF

diff expected actual

docker exec pki certutil -K -d nssdb3 | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+\(\S\+\)/\2 0x\1/p' output > actual

# CA signing key should not be present
cat > expected << EOF
sslserver $(cat sslserver.key_id)
audit_signing $(cat audit_signing.key_id)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import PKCS #12 file without CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import PKCS #12 file without user certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -d nssdb4 pkcs12-import \
    --pkcs12 test.p12 \
    --password Secret.123 \
    --no-user-certs

docker exec pki certutil -L -d nssdb4 | tail -n +5 | tee output
sed -n 's/^\(\S\+\)\s*\(\S\+\)\s*$/\1 \2/p' output > actual

# only CA signing cert should be present
cat > expected << EOF
ca_signing CT,C,C
EOF

diff expected actual

docker exec pki certutil -K -d nssdb4 | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+\(\S\+\)/\2 0x\1/p' output > actual

# no keys should be present
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import PKCS #12 file without user certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-pkcs12-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-pkcs12-test PASSED ===="
