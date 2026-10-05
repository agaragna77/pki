#!/bin/bash
# Generated TMT port of .github/workflows/ca-existing-certs-test.yml
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
    docker rm -f ds pki 2>/dev/null || true
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

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ca_signing.csr
docker exec pki pki \
    nss-cert-issue \
    --csr ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

# check original cert
docker exec pki pki \
    nss-cert-show \
    ca_signing | tee ca_signing.crt.before

# check original key
docker exec pki pki \
    nss-key-find \
    --nickname ca_signing | tee ca_signing.key.before

docker exec pki pki nss-cert-verify \
    --cert-usage SSLCA \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --csr ca_ocsp_signing.csr
docker exec pki pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr ca_ocsp_signing.csr \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --cert ca_ocsp_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_ocsp_signing.crt \
    ca_ocsp_signing

# check original cert
docker exec pki pki \
    nss-cert-show \
    ca_ocsp_signing | tee ca_ocsp_signing.crt.before

# check original key
docker exec pki pki \
    nss-key-find \
    --nickname ca_ocsp_signing | tee ca_ocsp_signing.key.before

docker exec pki pki nss-cert-verify \
    --cert-usage StatusResponder \
    ca_ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --csr ca_audit_signing.csr
docker exec pki pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr ca_audit_signing.csr \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --cert ca_audit_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_audit_signing.crt \
    --trust ,,P \
    ca_audit_signing

# check original cert
docker exec pki pki \
    nss-cert-show \
    ca_audit_signing | tee ca_audit_signing.crt.before

# check original key
docker exec pki pki \
    nss-key-find \
    --nickname ca_audit_signing | tee ca_audit_signing.key.before

docker exec pki pki nss-cert-verify \
    --cert-usage ObjectSigner \
    ca_audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr subsystem.csr
docker exec pki pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert subsystem.crt

docker exec pki pki nss-cert-import \
    --cert subsystem.crt \
    subsystem

# check original cert
docker exec pki pki \
    nss-cert-show \
    subsystem | tee subsystem.crt.before

# check original key
docker exec pki pki \
    nss-key-find \
    --nickname subsystem | tee subsystem.key.before

docker exec pki pki nss-cert-verify \
    --cert-usage SSLClient \
    subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=pki.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr
docker exec pki pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert sslserver.crt

docker exec pki pki nss-cert-import \
    --cert sslserver.crt \
    sslserver

# check original cert
docker exec pki pki \
    nss-cert-show \
    sslserver | tee sslserver.crt.before

# check original key
docker exec pki pki \
    nss-key-find \
    --nickname sslserver | tee sslserver.key.before

docker exec pki pki nss-cert-verify \
    --cert-usage SSLServer \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    pkcs12-export \
    --pkcs12 ca-certs.p12 \
    --password Secret.123 \
    ca_signing \
    ca_ocsp_signing \
    ca_audit_signing \
    subsystem \
    sslserver
docker exec pki pki \
    pkcs12-cert-find \
    --pkcs12 ca-certs.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create self-signed admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec pki pki \
    nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr admin.csr

# create self-signed cert
docker exec pki pki \
    nss-cert-issue \
    --csr admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert admin.crt

# import cert
docker exec pki pki \
    nss-cert-import \
    --cert admin.crt \
    caadmin

# check cert
docker exec pki pki nss-cert-show caadmin

# cert should be invalid
docker exec pki pki nss-cert-verify caadmin \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ERROR: Invalid certificate: Unable to validate certificate signature: CN=Administrator
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create self-signed admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with existing system certs and self-signed admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# run step 1
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_external=True \
    -D pki_external_step_two=False \
    -v

# run step 2
rc=0
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_external=True \
    -D pki_external_step_two=True \
    -D pki_pkcs12_path=ca-certs.p12 \
    -D pki_pkcs12_password=Secret.123 \
    -D pki_ca_signing_csr_path=ca_signing.csr \
    -D pki_ocsp_signing_csr_path=ca_ocsp_signing.csr \
    -D pki_audit_signing_csr_path=ca_audit_signing.csr \
    -D pki_subsystem_csr_path=subsystem.csr \
    -D pki_sslserver_csr_path=sslserver.csr \
    -D pki_admin_cert_path=admin.crt \
    -D pki_admin_csr_path=admin.csr \
    -v \
    || rc=$?

# pkispawn should fail
[ $rc -ne 0 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with existing system certs and self-signed admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA-signed admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# remove old cert
docker exec pki pki nss-cert-del caadmin

# create CA-signed cert
docker exec pki pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert admin.crt

# import new cert
docker exec pki pki \
    nss-cert-import \
    --cert admin.crt \
    caadmin

# check new cert
docker exec pki pki nss-cert-show caadmin

# cert should be valid
docker exec pki pki nss-cert-verify caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA-signed admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with existing system certs and CA-signed admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# run step 1
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_external=True \
    -D pki_external_step_two=False \
    -v

# run step 2
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_external=True \
    -D pki_external_step_two=True \
    -D pki_pkcs12_path=ca-certs.p12 \
    -D pki_pkcs12_password=Secret.123 \
    -D pki_ca_signing_csr_path=ca_signing.csr \
    -D pki_ocsp_signing_csr_path=ca_ocsp_signing.csr \
    -D pki_audit_signing_csr_path=ca_audit_signing.csr \
    -D pki_subsystem_csr_path=subsystem.csr \
    -D pki_sslserver_csr_path=sslserver.csr \
    -D pki_admin_cert_path=admin.crt \
    -D pki_admin_csr_path=admin.csr \
    -v

# pkispawn should succeed
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with existing system certs and CA-signed admin cert (rc=$_rc)" >&2
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

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    ca_signing | tee ca_signing.crt.after

# cert should not change
diff ca_signing.crt.before ca_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname ca_signing | tee ca_signing.key.after

# key should not change
diff ca_signing.key.before ca_signing.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    ca_ocsp_signing | tee ca_ocsp_signing.crt.after

# cert should not change
diff ca_ocsp_signing.crt.before ca_ocsp_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname ca_ocsp_signing | tee ca_ocsp_signing.key.after

# key should not change
diff ca_ocsp_signing.key.before ca_ocsp_signing.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    ca_audit_signing | tee ca_audit_signing.crt.after

# cert should not change
diff ca_audit_signing.crt.before ca_audit_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname ca_audit_signing | tee ca_audit_signing.key.after

# key should not change
diff ca_audit_signing.key.before ca_audit_signing.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    subsystem | tee subsystem.crt.after

# cert should not change
diff subsystem.crt.before subsystem.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname subsystem | tee subsystem.key.after

# key should not change
diff subsystem.key.before subsystem.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    sslserver | tee sslserver.crt.after

# cert should not change
diff sslserver.crt.before sslserver.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname sslserver | tee sslserver.key.after

# key should not change
diff sslserver.key.before sslserver.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
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

step "Check DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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
    echo "==== ca-existing-certs-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-existing-certs-test PASSED ===="
