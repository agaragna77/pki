#!/bin/bash
# Generated TMT port of .github/workflows/PKCS10Client-test.yml
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

step "Install ASN.1 parser"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y dumpasn1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install ASN.1 parser (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert with RSA key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-create --force

docker exec pki pki \
    nss-cert-request \
    --key-type RSA \
    --subject "CN=Certificate Authority" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ca_signing.csr

docker exec pki pki \
    nss-cert-issue \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ca_signing.crt

docker exec pki pki \
    nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert with RSA key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert request with RSA key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki PKCS10Client \
    -d /root/.dogtag/nssdb \
    -a rsa \
    -n "CN=pki.example.com" \
    -o sslserver.csr \
    -v | tee output

# check PEM CSR
docker exec pki cat sslserver.csr

# check CSR with OpenSSL
docker exec pki openssl req -in sslserver.csr -text -noout

# convert CSR into DER
docker exec pki openssl req -in sslserver.csr -outform der -out sslserver.der

# Currently PKCS10Client generates an invalid CSR
# so dumpasn1 will fail with the following message:
#   Error: Object has zero length.
#
# TODO: Fix PKCS10Client to generate a valid CSR

# display ASN.1 CSR
docker exec pki dumpasn1 sslserver.der || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert request with RSA key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
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
    nss-cert-import \
    --cert sslserver.crt \
    sslserver

# get key ID
docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+NSS Certificate DB:sslserver$/\1/p' output > sslserver_key_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,u" > expected

docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^sslserver\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected

docker exec pki pki nss-cert-show sslserver | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify key type"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo rsa > expected

docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+NSS Certificate DB:sslserver$/\1/p' output > actual
diff actual expected

docker exec pki pki nss-key-find --nickname sslserver | tee output
sed -n 's/\s*Type:\s*\(\S\+\)\s*$/\L\1/p' output > actual
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify key type (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Delete SSL server cert and key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-del --remove-key sslserver

docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output

# SSL server cert should not exist
echo "ca_signing CTu,Cu,Cu" > expected
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual
diff expected actual

docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output

# SSL server key should not exist
echo "NSS Certificate DB:ca_signing" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Delete SSL server cert and key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert with EC key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-create --force

docker exec pki pki \
    nss-cert-request \
    --key-type EC \
    --subject "CN=Certificate Authority" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ca_signing.csr

docker exec pki pki \
    nss-cert-issue \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ca_signing.crt

docker exec pki pki \
    nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert with EC key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert request with EC key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki PKCS10Client \
    -d /root/.dogtag/nssdb \
    -a ec \
    -n "CN=pki.example.com" \
    -o sslserver.csr \
    -v | tee output

# check PEM CSR
docker exec pki cat sslserver.csr

# check CSR with OpenSSL
docker exec pki openssl req -in sslserver.csr -text -noout

# convert CSR into DER
docker exec pki openssl req -in sslserver.csr -outform der -out sslserver.der

# Currently PKCS10Client generates an invalid CSR
# so dumpasn1 will fail with the following message:
#   Error: Object has zero length.
#
# TODO: Fix PKCS10Client to generate a valid CSR

# display ASN.1 CSR
docker exec pki dumpasn1 sslserver.der || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert request with EC key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
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
    nss-cert-import \
    --cert sslserver.crt \
    sslserver

# get key ID
docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^<.*>\s\+\S\+\s\+\(\S\+\)\s\+NSS Certificate DB:sslserver$/\1/p' output > sslserver_key_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,u" > expected

docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^sslserver\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected

docker exec pki pki nss-cert-show sslserver | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify key type"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo ec > expected

docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output
sed -n 's/^<.*>\s\+\(\S\+\)\s\+\S\+\s\+NSS Certificate DB:sslserver$/\1/p' output > actual
diff actual expected

docker exec pki pki nss-key-find --nickname sslserver | tee output
sed -n 's/\s*Type:\s*\(\S\+\)\s*$/\L\1/p' output > actual
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify key type (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Delete SSL server cert and key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-del --remove-key sslserver

docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output

# SSL server cert should not exist
echo "ca_signing CTu,Cu,Cu" > expected
sed -n -e '1,4d' -e 's/^\(.*\S\)\s\+\(\S\+\)\s*$/\1 \2/p' output > actual
diff expected actual

docker exec pki certutil -K -d /root/.dogtag/nssdb | tee output

# SSL server key should not exist
echo "NSS Certificate DB:ca_signing" > expected
sed -n 's/^<.*>\s\+\S\+\s\+\S\+\s\+\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Delete SSL server cert and key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== PKCS10Client-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== PKCS10Client-test PASSED ===="
