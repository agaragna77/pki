#!/bin/bash
# Generated TMT port of .github/workflows/pki-nss-pqc-test.yml
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

docker exec pki dnf install -y dumpasn1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up runner container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file
echo "Secret.123" > password.txt

# create password config
echo "internal=$(cat password.txt)" > password.conf

# create password-protected NSS database
docker exec pki pki \
    -C $SHARED/password.txt \
    nss-create
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-create \
    --key-type MLDSA \
    --key-id-file $SHARED/ca_signing.key-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key type should be ML-DSA
echo "mldsa" > expected
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+.*$/\1/p' output > actual

diff expected actual

# list all keys
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-find \
    | tee output

# key type and algorithm should be ML-DSA
cat > expected << EOF
Type: ML-DSA-65
Algorithm: ML-DSA
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

# check key with inline password
docker exec pki pki \
    -c $(cat password.txt) \
    nss-key-show \
    --key-id-file $SHARED/ca_signing.key-id \
    | tee output

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

# check key with password file
docker exec pki pki \
    -C $SHARED/password.txt \
    nss-key-show \
    --key-id-file $SHARED/ca_signing.key-id \
    | tee output

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

# check key with password config
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-show \
    --key-id-file $SHARED/ca_signing.key-id \
    | tee output

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

# check key with password prompt
cat password.txt | docker exec -i pki pki \
    nss-key-show \
    --key-id-file $SHARED/ca_signing.key-id \
    | tee output

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing CSR with existing key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-request \
    --key-id-file $SHARED/ca_signing.key-id \
    --subject "CN=Certificate Authority" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ca_signing.csr

docker exec pki openssl req -text -noout -in ca_signing.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing CSR with existing key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue self-signed CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-issue \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ca_signing.crt

docker exec pki openssl x509 -text -noout -in ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue self-signed CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert ca_signing.crt \
    --trust "CT,C,C" \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# trust flags should be CTu,Cu,Cu
echo "CTu,Cu,Cu" > expected
sed -n 's/^ca_signing\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    ca_signing \
    | tee output

# trust flags should be CTu,Cu,Cu
echo "CTu,Cu,Cu" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server CSR with new key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-request \
    --key-type MLDSA \
    --subject "CN=pki.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr

# CSR should be created
docker exec pki openssl req -text -noout -in sslserver.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server CSR with new key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-issue \
    --issuer ca_signing \
    --csr sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert sslserver.crt

docker exec pki openssl x509 -text -noout -in sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert sslserver.crt \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key type should be ML-DSA
echo "mldsa" > expected
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+NSS Certificate DB:sslserver$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-find \
    --nickname sslserver | tee output

# key type and algorithm should be ML-DSA
cat > expected << EOF
Type: ML-DSA-65
Algorithm: ML-DSA
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/^sslserver\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    sslserver | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove SSL server cert and key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-del \
    sslserver \
    --remove-key

docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# cert should be removed
echo "ca_signing CTu,Cu,Cu" > expected
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual
diff expected actual

docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key should be removed
echo "NSS Certificate DB:ca_signing" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual
diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    sslserver \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# cert should be removed
cat > expected << EOF
ERROR: Certificate not found: sslserver
EOF

diff expected stderr

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-export \
    sslserver \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# cert should be removed
cat > expected << EOF
ERROR: Certificate not found: sslserver
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove SSL server cert and key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create audit signing CSR with new key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-request \
    --key-type MLDSA \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --csr audit_signing.csr

docker exec pki openssl req -text -noout -in audit_signing.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create audit signing CSR with new key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-issue \
    --issuer ca_signing \
    --csr audit_signing.csr \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --cert audit_signing.crt

docker exec pki openssl x509 -text -noout -in audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert audit_signing.crt \
    audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check audit signing key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key type should be ML-DSA
echo "mldsa" > expected
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+NSS Certificate DB:audit_signing$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-find \
    --nickname audit_signing | tee output

# key type and algorithm should be ML-DSA
cat > expected << EOF
Type: ML-DSA-65
Algorithm: ML-DSA
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check audit signing key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/^audit_signing\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    audit_signing | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Modify audit signing cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-mod \
    --trust-flags "u,u,P" \
    audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Modify audit signing cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check audit signing cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# trust flags should be u,u,Pu
echo "u,u,Pu" > expected
sed -n 's/^audit_signing\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    audit_signing \
    | tee output

# trust flags should be u,u,Pu
echo "u,u,Pu" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check audit signing cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove audit signing cert and key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-del \
    audit_signing \
    --remove-key

docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# cert should be removed
echo "ca_signing CTu,Cu,Cu" > expected
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual

diff expected actual

docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key should be removed
echo "NSS Certificate DB:ca_signing" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove audit signing cert and key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA storage CSR with new key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-request \
    --type crmf \
    --key-type MLKEM \
    --subject "CN=KRA Storage Certificate" \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --csr kra_storage.csr

# CSR should be created
docker exec pki AtoB kra_storage.csr kra_storage.der
docker exec pki dumpasn1 kra_storage.der
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA storage CSR with new key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-issue \
    --issuer ca_signing \
    --csr-type crmf \
    --csr kra_storage.csr \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --cert kra_storage.crt

docker exec pki openssl x509 -text -noout -in kra_storage.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert kra_storage.crt \
    kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA storage key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key type should be ML-KEM
echo "mlkem" > expected
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+NSS Certificate DB:kra_storage$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-find \
    --nickname kra_storage | tee output

# key type and algorithm should be ML-KEM
cat > expected << EOF
Type: ML-KEM-768
Algorithm: ML-KEM
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA storage key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/^kra_storage\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    kra_storage | tee output

# trust flags should be u,u,u
echo "u,u,u" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA storage cert and key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-del \
    kra_storage \
    --remove-key

docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# cert should be removed
echo "ca_signing CTu,Cu,Cu" > expected
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual
diff expected actual

docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key should be removed
echo "NSS Certificate DB:ca_signing" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual
diff expected actual

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-show \
    kra_storage \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# cert should be removed
cat > expected << EOF
ERROR: Certificate not found: kra_storage
EOF

diff expected stderr

docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-export \
    kra_storage \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# cert should be removed
cat > expected << EOF
ERROR: Certificate not found: kra_storage
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA storage cert and key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-cert-del \
    ca_signing

docker exec pki certutil -L \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# cert should be removed
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual

diff /dev/null actual

docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key should not be removed
echo "(orphan)" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA signing key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -f $SHARED/password.conf \
    nss-key-del \
    --key-id-file $SHARED/ca_signing.key-id

docker exec pki certutil -K \
    -d /root/.dogtag/nssdb \
    -f $SHARED/password.txt \
    | tee output

# key should be removed
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA signing key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-nss-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-nss-pqc-test PASSED ===="
