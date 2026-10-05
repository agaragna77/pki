#!/bin/bash
# Generated TMT port of .github/workflows/ca-existing-nssdb-test.yml
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

step "Create PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create
docker exec pki pki-server nss-create --no-password
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    ca_signing
docker exec pki pki-server cert-create \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    ca_signing
docker exec pki pki-server cert-import ca_signing

# check original cert
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_signing | tee ca_signing.crt.before

# check original key
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-key-find \
    --nickname ca_signing | tee ca_signing.key.before
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
docker exec pki pki-server cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    ca_ocsp_signing
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    ca_ocsp_signing
docker exec pki pki-server cert-import ca_ocsp_signing

# check original cert
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_ocsp_signing | tee ca_ocsp_signing.crt.before

# check original key
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-key-find \
    --nickname ca_ocsp_signing | tee ca_ocsp_signing.key.before
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
docker exec pki pki-server cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    ca_audit_signing
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    ca_audit_signing
docker exec pki pki-server cert-import ca_audit_signing

# check original cert
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    ca_audit_signing | tee ca_audit_signing.crt.before

# check original key
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-key-find \
    --nickname ca_audit_signing | tee ca_audit_signing.key.before
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
docker exec pki pki-server cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    subsystem
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    subsystem
docker exec pki pki-server cert-import subsystem

# check original cert
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    subsystem | tee subsystem.crt.before

# check original key
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-key-find \
    --nickname subsystem | tee subsystem.key.before
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
docker exec pki pki-server cert-request \
    --subject "CN=pki.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    sslserver
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    sslserver
docker exec pki pki-server cert-import sslserver

# check original cert
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-show \
    sslserver | tee sslserver.crt.before

# check original key
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-key-find \
    --nickname sslserver | tee sslserver.key.before
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr admin.csr
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert admin.crt

docker exec pki pki nss-cert-import \
    --cert admin.crt \
    caadmin

docker exec pki pki \
    nss-cert-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with existing NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_admin_cert_path=admin.crt \
    -D pki_admin_csr_path=admin.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with existing NSS database (rc=$_rc)" >&2
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
    nss-cert-show \
    ca_signing | tee ca_signing.crt.after

# cert should not change
diff ca_signing.crt.before ca_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
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
    nss-cert-show \
    ca_ocsp_signing | tee ca_ocsp_signing.crt.after

# cert should not change
diff ca_ocsp_signing.crt.before ca_ocsp_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
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
    nss-cert-show \
    ca_audit_signing | tee ca_audit_signing.crt.after

# cert should not change
diff ca_audit_signing.crt.before ca_audit_signing.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
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
    nss-cert-show \
    subsystem | tee subsystem.crt.after

# cert should not change
diff subsystem.crt.before subsystem.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
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
    nss-cert-show \
    sslserver | tee sslserver.crt.after

# cert should not change
diff sslserver.crt.before sslserver.crt.after

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
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
docker exec pki pki nss-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

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
    echo "==== ca-existing-nssdb-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-existing-nssdb-test PASSED ===="
