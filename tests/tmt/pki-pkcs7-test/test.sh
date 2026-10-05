#!/bin/bash
# Generated TMT port of .github/workflows/pki-pkcs7-test.yml
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

step "Check pki pkcs7 CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs7
docker exec pki pki pkcs7 --help

docker exec pki pki pkcs7-export --help
docker exec pki pki pkcs7-import --help

docker exec pki pki pkcs7-cert-find --help
docker exec pki pki pkcs7-cert-export --help
docker exec pki pki pkcs7-cert-import --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki pkcs7 CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate CA signing cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "CN=Certificate Authority" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ca_signing.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate CA signing cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue self-signed CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-issue \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ca_signing.crt
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
docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate SSL server cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "CN=localhost.localdomain" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate SSL server cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert signed by CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-issue \
    --issuer ca_signing \
    --csr sslserver.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert signed by CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-import sslserver --cert sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export SSL server cert chain into PKCS #7 chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs7-export sslserver --pkcs7 cert_chain.p7b
docker exec pki pki pkcs7-cert-find --pkcs7 cert_chain.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export SSL server cert chain into PKCS #7 chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Convert cert chain into separate PEM certificates"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs7-cert-export \
    --pkcs7 cert_chain.p7b \
    --output-prefix cert- \
    --output-suffix .pem
docker exec pki cat cert-0.pem
docker exec pki cat cert-1.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Convert cert chain into separate PEM certificates (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Merge PEM certificates into a PKCS #7 chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki rm -f cert_chain.p7b
docker exec pki pki pkcs7-cert-import \
    --pkcs7 cert_chain.p7b \
    --input-file cert-0.pem
docker exec pki pki pkcs7-cert-import \
    --pkcs7 cert_chain.p7b \
    --input-file cert-1.pem \
    --append
docker exec pki pki pkcs7-cert-find --pkcs7 cert_chain.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Merge PEM certificates into a PKCS #7 chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove certs from NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-del sslserver
docker exec pki pki nss-cert-del ca_signing
docker exec pki certutil -L -d /root/.dogtag/nssdb
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove certs from NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import PKCS #7 chain into NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs7-import sslserver --pkcs7 cert_chain.p7b
docker exec pki certutil -L -d /root/.dogtag/nssdb
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import PKCS #7 chain into NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify CA signing cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^Certificate Authority *\(\S\+\)/\1/p' output > actual
echo "CTu,Cu,Cu" > expected
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify CA signing cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify SSL server cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^sslserver *\(\S\+\)/\1/p' output > actual
echo "u,u,u" > expected
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify SSL server cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Convert PKCS #7 chain into a series of PEM certificates"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs7-cert-export \
    --pkcs7 cert_chain.p7b \
    --output-file cert_chain.pem
docker exec pki cat cert_chain.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Convert PKCS #7 chain into a series of PEM certificates (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove certs from NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-del sslserver
docker exec pki pki nss-cert-del "Certificate Authority"
docker exec pki certutil -L -d /root/.dogtag/nssdb
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove certs from NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import PEM certificates into NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki rm -f cert_chain.p7b
docker exec pki pki pkcs7-cert-import \
    --pkcs7 cert_chain.p7b \
    --input-file cert_chain.pem
docker exec pki pki pkcs7-import sslserver --pkcs7 cert_chain.p7b
docker exec pki certutil -L -d /root/.dogtag/nssdb
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import PEM certificates into NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify CA signing cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^Certificate Authority *\(\S\+\)/\1/p' output > actual
echo "CTu,Cu,Cu" > expected
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify CA signing cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify SSL server cert trust flags"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -L -d /root/.dogtag/nssdb | tee output
sed -n 's/^sslserver *\(\S\+\)/\1/p' output > actual
echo "u,u,u" > expected
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify SSL server cert trust flags (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-pkcs7-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-pkcs7-test PASSED ===="
