#!/bin/bash
# Generated TMT port of .github/workflows/ca-profile-caStorageCert-test.yml
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

docker exec pki dnf install -y dumpasn1
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

step "Enroll cert using PKCS10Client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate PKCS #10 request
docker exec pki PKCS10Client \
    -d /root/.dogtag/nssdb \
    -n "CN=test-PKCS10Client" \
    -o test-PKCS10Client.csr

docker exec pki cat test-PKCS10Client.csr

docker exec pki AtoB test-PKCS10Client.csr test-PKCS10Client.der

# ignore invalid PKCS #10 data
docker exec pki dumpasn1 test-PKCS10Client.der || true

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caStorageCert \
    --csr-file test-PKCS10Client.csr \
    --output-file test-PKCS10Client.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-PKCS10Client.crt \
    test-PKCS10Client

docker exec pki pki nss-cert-show test-PKCS10Client | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-PKCS10Client
  Subject DN: CN=test-PKCS10Client
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using PKCS10Client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert using CRMFPopClient without POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CRMF request
docker exec pki CRMFPopClient \
    -d /root/.dogtag/nssdb \
    -p "" \
    -n "CN=test-CRMFPopClient-without-POP" \
    -q POP_NONE \
    -o test-CRMFPopClient-without-POP.csr \
    -v

docker exec pki cat test-CRMFPopClient-without-POP.csr

docker exec pki AtoB test-CRMFPopClient-without-POP.csr test-CRMFPopClient-without-POP.der
docker exec pki dumpasn1 test-CRMFPopClient-without-POP.der

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caStorageCert \
    --subject CN=test-CRMFPopClient-without-POP \
    --csr-file test-CRMFPopClient-without-POP.csr \
    --output-file test-CRMFPopClient-without-POP.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-CRMFPopClient-without-POP.crt \
    test-CRMFPopClient-without-POP

docker exec pki pki nss-cert-show test-CRMFPopClient-without-POP | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-CRMFPopClient-without-POP
  Subject DN: CN=test-CRMFPopClient-without-POP
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using CRMFPopClient without POP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert using CRMFPopClient with POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CRMF request
docker exec pki CRMFPopClient \
    -d /root/.dogtag/nssdb \
    -p "" \
    -n "CN=test-CRMFPopClient-with-POP" \
    -o test-CRMFPopClient-with-POP.csr \
    -v

docker exec pki cat test-CRMFPopClient-with-POP.csr

docker exec pki AtoB test-CRMFPopClient-with-POP.csr test-CRMFPopClient-with-POP.der
docker exec pki dumpasn1 test-CRMFPopClient-with-POP.der

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caStorageCert \
    --subject CN=test-CRMFPopClient-with-POP \
    --csr-file test-CRMFPopClient-with-POP.csr \
    --output-file test-CRMFPopClient-with-POP.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-CRMFPopClient-with-POP.crt \
    test-CRMFPopClient-with-POP

docker exec pki pki nss-cert-show test-CRMFPopClient-with-POP | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-CRMFPopClient-with-POP
  Subject DN: CN=test-CRMFPopClient-with-POP
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using CRMFPopClient with POP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert using PKI CLI with PKCS #10 request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate PKCS #10 request
docker exec pki pki nss-cert-request \
    --subject "CN=test-PKI-CLI-PKCS10" \
    --csr test-PKI-CLI-PKCS10.csr

docker exec pki cat test-PKI-CLI-PKCS10.csr

docker exec pki AtoB test-PKI-CLI-PKCS10.csr test-PKI-CLI-PKCS10.der

# ignore invalid PKCS #10 data
docker exec pki dumpasn1 test-PKI-CLI-PKCS10.der || true

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caStorageCert \
    --csr-file test-PKI-CLI-PKCS10.csr \
    --output-file test-PKI-CLI-PKCS10.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-PKI-CLI-PKCS10.crt \
    test-PKI-CLI-PKCS10

docker exec pki pki nss-cert-show test-PKI-CLI-PKCS10 | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-PKI-CLI-PKCS10
  Subject DN: CN=test-PKI-CLI-PKCS10
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using PKI CLI with PKCS #10 request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert using PKI CLI with CRMF request without POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CRMF request
docker exec pki pki nss-cert-request \
    --type crmf \
    --subject "CN=test-PKI-CLI-CRMF-without-POP" \
    --csr test-PKI-CLI-CRMF-without-POP.csr

docker exec pki cat test-PKI-CLI-CRMF-without-POP.csr

docker exec pki AtoB test-PKI-CLI-CRMF-without-POP.csr test-PKI-CLI-CRMF-without-POP.der
docker exec pki dumpasn1 test-PKI-CLI-CRMF-without-POP.der

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caStorageCert \
    --subject CN=test-PKI-CLI-CRMF-without-POP \
    --csr-file test-PKI-CLI-CRMF-without-POP.csr \
    --output-file test-PKI-CLI-CRMF-without-POP.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-PKI-CLI-CRMF-without-POP.crt \
    test-PKI-CLI-CRMF-without-POP

docker exec pki pki nss-cert-show test-PKI-CLI-CRMF-without-POP | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-PKI-CLI-CRMF-without-POP
  Subject DN: CN=test-PKI-CLI-CRMF-without-POP
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using PKI CLI with CRMF request without POP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert using PKI CLI with CRMF request with POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CRMF request
docker exec pki pki nss-cert-request \
    --type crmf \
    --pop \
    --subject "CN=test-PKI-CLI-CRMF-with-POP" \
    --csr test-PKI-CLI-CRMF-with-POP.csr

docker exec pki cat test-PKI-CLI-CRMF-with-POP.csr

docker exec pki AtoB test-PKI-CLI-CRMF-with-POP.csr test-PKI-CLI-CRMF-with-POP.der
docker exec pki dumpasn1 test-PKI-CLI-CRMF-with-POP.der

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caStorageCert \
    --subject CN=test-PKI-CLI-CRMF-with-POP \
    --csr-file test-PKI-CLI-CRMF-with-POP.csr \
    --output-file test-PKI-CLI-CRMF-with-POP.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-PKI-CLI-CRMF-with-POP.crt \
    test-PKI-CLI-CRMF-with-POP

docker exec pki pki nss-cert-show test-PKI-CLI-CRMF-with-POP | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
  Nickname: test-PKI-CLI-CRMF-with-POP
  Subject DN: CN=test-PKI-CLI-CRMF-with-POP
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert using PKI CLI with CRMF request with POP (rc=$_rc)" >&2
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

step "Check for core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -l
docker exec pki find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for core dumps (rc=$_rc)" >&2
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
    echo "==== ca-profile-caStorageCert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-profile-caStorageCert-test PASSED ===="
