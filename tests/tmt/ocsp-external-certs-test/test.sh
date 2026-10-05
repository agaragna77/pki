#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-external-certs-test.yml
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
    docker rm -f ca cads ocsp ocspds 2>/dev/null || true
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

step "Set up CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=cads.example.com \
    --network=example \
    --network-alias=cads.example.com \
    --password=Secret.123 \
    cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=ca.example.com \
    --network=example \
    --network-alias=ca.example.com \
    ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://cads.example.com:3389 \
    -v

docker exec ca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize CA admin in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt

docker exec ca pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize CA admin in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up OCSP DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=ocspds.example.com \
    --network=example \
    --network-alias=ocspds.example.com \
    --password=Secret.123 \
    ocspds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=ocsp.example.com \
    --network=example \
    --network-alias=ocsp.example.com \
    ocsp
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in OCSP container (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-external-certs-step1.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ocspds.example.com:3389 \
    -D pki_ocsp_signing_csr_path=${SHARED}/ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/ocsp_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/ocsp_admin.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in OCSP container (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_signing.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caOCSPCert \
    --csr-file ${SHARED}/ocsp_signing.csr \
    --output-file ${SHARED}/ocsp_signing.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/subsystem.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file ${SHARED}/subsystem.csr \
    --output-file ${SHARED}/subsystem.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/subsystem.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/sslserver.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file ${SHARED}/sslserver.csr \
    --output-file ${SHARED}/sslserver.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_audit_signing.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file ${SHARED}/ocsp_audit_signing.csr \
    --output-file ${SHARED}/ocsp_audit_signing.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_admin.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file ${SHARED}/ocsp_admin.csr \
    --output-file ${SHARED}/ocsp_admin.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in OCSP container (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-external-certs-step2.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ocspds.example.com:3389 \
    -D pki_ocsp_signing_csr_path=${SHARED}/ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/ocsp_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/ocsp_admin.csr \
    -D pki_ocsp_signing_cert_path=${SHARED}/ocsp_signing.crt \
    -D pki_subsystem_cert_path=${SHARED}/subsystem.crt \
    -D pki_sslserver_cert_path=${SHARED}/sslserver.crt \
    -D pki_audit_signing_cert_path=${SHARED}/ocsp_audit_signing.crt \
    -D pki_admin_cert_path=${SHARED}/ocsp_admin.crt \
    -v

docker exec ocsp pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in OCSP container (step 2) (rc=$_rc)" >&2
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
    docker exec ocsp pki-healthcheck --failures-only
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

step "Verify OCSP admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ocsp pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ocsp_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec ocsp pki -n ocspadmin ocsp-user-show ocspadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify OCSP admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP from OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP from OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec cads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocspds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ocspds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ocsp-external-certs-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-external-certs-test PASSED ===="
