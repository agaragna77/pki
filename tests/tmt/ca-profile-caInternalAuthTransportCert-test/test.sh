#!/bin/bash
# Generated TMT port of .github/workflows/ca-profile-caInternalAuthTransportCert-test.yml
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

docker exec pki dnf install -y jq dumpasn1
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
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
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

step "Configure caInternalAuthTransportCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# allow ML-KEM-768 via allowedKeys (after RSA allowedKeys block)
docker exec pki sed -i \
    -e '/^policyset\.transportCertSet\.3\.constraint\.params\.allowedKeys\.RSA\.4096=true/a policyset.transportCertSet.3.constraint.params.allowedKeys.MLKEM.768=true' \
    /var/lib/pki/pki-tomcat/ca/profiles/ca/caInternalAuthTransportCert.cfg

# restart CA
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure caInternalAuthTransportCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA admin"
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SD session"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# authenticate as security domain admin
docker exec pki curl \
    -k \
    -s \
    -H "Accept: application/json" \
    --user caadmin:Secret.123 \
    --cookie-jar cookies \
    https://pki.example.com:8443/ca/v2/account/login \
    | python -m json.tool

# create security domain session
docker exec pki curl \
    -k \
    -s \
    --cookie cookies \
    "https://pki.example.com:8443/ca/v2/securityDomain/installToken?hostname=pki.example.com&subsystem=CA" \
    | python -m json.tool \
    | tee session.json

# TODO: implement pki sd-session-create
# docker exec pki pki \
#     -u caadmin \
#     -w Secret.123 \
#     sd-session-create \
#     --session-file session.json

# store install token
jq -r '.token' session.json > install-token
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SD session (rc=$_rc)" >&2
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
    -a mlkem \
    -l 768 \
    -t false \
    -f caInternalAuthTransportCert \
    -n "CN=test-CRMFPopClient-without-POP" \
    -q POP_NONE \
    -o test-CRMFPopClient-without-POP.csr

docker exec pki certutil -K -d /root/.dogtag/nssdb

docker exec pki cat test-CRMFPopClient-without-POP.csr

docker exec pki AtoB test-CRMFPopClient-without-POP.csr test-CRMFPopClient-without-POP.der
docker exec pki dumpasn1 test-CRMFPopClient-without-POP.der

# issue cert
docker exec pki pki \
    ca-cert-issue \
    --install-token $SHARED/install-token \
    --request-type crmf \
    --profile caInternalAuthTransportCert \
    --subject CN=test-CRMFPopClient-without-POP \
    --csr-file test-CRMFPopClient-without-POP.csr \
    --output-file test-CRMFPopClient-without-POP.crt

docker exec pki openssl x509 -text -noout -in test-CRMFPopClient-without-POP.crt

# import cert
docker exec pki pki nss-cert-import \
    --cert test-CRMFPopClient-without-POP.crt \
    test-CRMFPopClient-without-POP

docker exec pki certutil -K -d /root/.dogtag/nssdb

docker exec pki pki nss-cert-show test-CRMFPopClient-without-POP | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

# the cert should match the key (trust attributes must be u,u,u)
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

step "Enroll cert using PKI CLI with CRMF request without POP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CRMF request
docker exec pki pki nss-cert-request \
    --type crmf \
    --key-type MLKEM \
    --subject "CN=test-PKI-CLI-CRMF-without-POP" \
    --csr test-PKI-CLI-CRMF-without-POP.csr

docker exec pki cat test-PKI-CLI-CRMF-without-POP.csr

docker exec pki AtoB test-PKI-CLI-CRMF-without-POP.csr test-PKI-CLI-CRMF-without-POP.der
docker exec pki dumpasn1 test-PKI-CLI-CRMF-without-POP.der

# issue cert
docker exec pki pki \
    ca-cert-issue \
    --install-token $SHARED/install-token \
    --request-type crmf \
    --profile caInternalAuthTransportCert \
    --subject CN=test-PKI-CLI-CRMF-without-POP \
    --csr-file test-PKI-CLI-CRMF-without-POP.csr \
    --output-file test-PKI-CLI-CRMF-without-POP.crt

docker exec pki openssl x509 -text -noout -in test-PKI-CLI-CRMF-without-POP.crt

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

# the cert should match the key (trust attributes must be u,u,u)
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

step "Remove SD session"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# remove security domain session
# TODO: implement REST API

# TODO: implement pki sd-session-del
# docker exec pki pki \
#     -u caadmin \
#     -w Secret.123 \
#     sd-session-del \
#     --session-file session.json
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove SD session (rc=$_rc)" >&2
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
    echo "==== ca-profile-caInternalAuthTransportCert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-profile-caInternalAuthTransportCert-test PASSED ===="
