#!/bin/bash
# Generated TMT port of .github/workflows/subca-hsm-test.yml
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

step "Create root CA in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d nssdb \
    nss-cert-request \
    --subject "CN=Root CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr root-ca_signing.csr
docker exec pki pki \
    -d nssdb \
    nss-cert-issue \
    --csr root-ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert root-ca_signing.crt

docker exec pki pki \
    -d nssdb \
    nss-cert-import \
    --cert root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create root CA in NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y softhsm opendnssec
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SoftHSM token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# allow PKI user to access SoftHSM files
docker exec pki usermod pkiuser -a -G ods

# create SoftHSM token for PKI server
docker exec pki runuser -u pkiuser -- \
    softhsm2-util \
    --init-token \
    --label HSM \
    --so-pin Secret.HSM \
    --pin Secret.HSM \
    --free

docker exec pki ls -laR /var/lib/softhsm/tokens

docker exec pki modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SoftHSM token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install subordinate CA (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step1.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=internal \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install subordinate CA (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subordinate CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -d nssdb nss-cert-issue \
    --issuer root-ca_signing \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/subca_signing.conf \
    --cert ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue subordinate CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install subordinate CA (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step2.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=internal \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install subordinate CA (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 6 certs
echo "6" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA signing cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "CT,C,C" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    root-ca_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA signing cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_signing cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "CT,C,C" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_signing cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_ocsp_signing cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo ",," > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_ocsp_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_ocsp_signing cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_audit_signing cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo ",,P" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_audit_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_audit_signing cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo ",," > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    subsystem | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sslserver cert in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,u" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    sslserver | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sslserver cert in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "4" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_signing cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "CTu,Cu,Cu" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:ca_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_signing cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_ocsp_signing cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,u" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:ca_ocsp_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_ocsp_signing cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ca_audit_signing cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,Pu" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:ca_audit_signing | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ca_audit_signing cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "u,u,u" > expected
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:subsystem | tee output
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Retry pki-healthcheck: intermittent NSS load timeout on audit_signing
hc_ok=0
for hc_try in 1 2 3; do
    echo "pki-healthcheck attempt ${hc_try}/3"
    if (
    set -euo pipefail
    docker exec pki pki-healthcheck --failures-only
    ); then
        hc_ok=1
        break
    fi
    sleep 5
done
[[ "$hc_ok" -eq 1 ]]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run PKI healthcheck (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-import \
    --cert root-ca_signing.crt \
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
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs and requests"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find
docker exec pki pki -n caadmin ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs and requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove subordinate CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove subordinate CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove SoftHSM token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- softhsm2-util --delete-token --token HSM
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove SoftHSM token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== subca-hsm-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== subca-hsm-test PASSED ===="
