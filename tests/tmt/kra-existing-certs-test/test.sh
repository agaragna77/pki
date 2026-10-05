#!/bin/bash
# Generated TMT port of .github/workflows/kra-existing-certs-test.yml
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
    docker rm -f ca kra 2>/dev/null || true
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v

docker exec ca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec ca pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec ca pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=kra.example.com \
    --network=example \
    --network-alias=kra.example.com \
    kra

# install CA signing cert for cert validation
docker exec kra pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail

docker exec kra pki nss-cert-request \
    --subject "CN=DRM Storage Certificate" \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --csr $SHARED/kra_storage.csr
docker exec ca openssl req -text -noout -in $SHARED/kra_storage.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caStorageCert \
    --csr-file $SHARED/kra_storage.csr \
    --output-file $SHARED/kra_storage.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_storage.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/kra_storage.crt \
    kra_storage

# check original cert
docker exec kra pki nss-cert-show \
    kra_storage | tee kra_storage.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname kra_storage | tee kra_storage.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage SSLClient \
    kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-request \
    --subject "CN=DRM Transport Certificate" \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    --csr $SHARED/kra_transport.csr
docker exec ca openssl req -text -noout -in $SHARED/kra_transport.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caTransportCert \
    --csr-file $SHARED/kra_transport.csr \
    --output-file $SHARED/kra_transport.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_transport.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/kra_transport.crt \
    kra_transport

# check original cert
docker exec kra pki nss-cert-show \
    kra_transport | tee kra_transport.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname kra_transport | tee kra_transport.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage SSLClient \
    kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --csr $SHARED/kra_audit_signing.csr
docker exec ca openssl req -text -noout -in $SHARED/kra_audit_signing.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file $SHARED/kra_audit_signing.csr \
    --output-file $SHARED/kra_audit_signing.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_audit_signing.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/kra_audit_signing.crt \
    --trust "u,u,Pu" \
    kra_audit_signing

# check original cert
docker exec kra pki nss-cert-show \
    kra_audit_signing | tee kra_audit_signing.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname kra_audit_signing | tee kra_audit_signing.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage ObjectSigner \
    kra_audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/subsystem.csr
docker exec ca openssl req -text -noout -in $SHARED/subsystem.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file $SHARED/subsystem.csr \
    --output-file $SHARED/subsystem.crt
docker exec ca openssl x509 -text -noout -in $SHARED/subsystem.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/subsystem.crt \
    subsystem

# check original cert
docker exec kra pki nss-cert-show \
    subsystem | tee subsystem.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname subsystem | tee subsystem.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage SSLClient \
    subsystem
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
docker exec kra pki nss-cert-request \
    --subject "CN=kra.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/sslserver.csr
docker exec ca openssl req -text -noout -in $SHARED/sslserver.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file $SHARED/sslserver.csr \
    --output-file $SHARED/sslserver.crt
docker exec ca openssl x509 -text -noout -in $SHARED/sslserver.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/sslserver.crt \
    sslserver

# check original cert
docker exec kra pki nss-cert-show \
    sslserver | tee sslserver.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname sslserver | tee sslserver.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage SSLServer \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/kra_admin.csr
docker exec ca openssl req -text -noout -in $SHARED/kra_admin.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file $SHARED/kra_admin.csr \
    --output-file $SHARED/kra_admin.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_admin.crt

docker exec kra pki nss-cert-import \
    --cert $SHARED/kra_admin.crt \
    kraadmin

# check original cert
docker exec kra pki nss-cert-show \
    kraadmin | tee kraadmin.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname kraadmin | tee kraadmin.key.before

docker exec kra pki nss-cert-verify \
    --cert-usage SSLClient \
    kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    pkcs12-export \
    --pkcs12 $SHARED/kra-certs.p12 \
    --password Secret.123 \
    kra_storage \
    kra_transport \
    kra_audit_signing \
    subsystem \
    sslserver
docker exec kra pki \
    pkcs12-cert-find \
    --pkcs12 $SHARED/kra-certs.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA with existing certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_security_domain_uri=https://ca.example.com:8443 \
    -D pki_issuing_ca_uri=https://ca.example.com:8443 \
    -D pki_server_pkcs12_path=$SHARED/kra-certs.p12 \
    -D pki_server_pkcs12_password=Secret.123 \
    -D pki_storage_csr_path=$SHARED/kra_storage.csr \
    -D pki_transport_csr_path=$SHARED/kra_transport.csr \
    -D pki_audit_signing_csr_path=$SHARED/kra_audit_signing.csr \
    -D pki_subsystem_csr_path=$SHARED/subsystem.csr \
    -D pki_sslserver_csr_path=$SHARED/sslserver.csr \
    -D pki_admin_cert_path=$SHARED/kra_admin.crt \
    -v

docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA with existing certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA storage cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_storage | tee kra_storage.crt.after

# cert should not change
diff kra_storage.crt.before kra_storage.crt.after

docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_storage | tee kra_storage.key.after

# key should not change
diff kra_storage.key.before kra_storage.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA storage cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA transport cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_transport | tee kra_transport.crt.after

# cert should not change
diff kra_transport.crt.before kra_transport.crt.after

docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_transport | tee kra_transport.key.after

# key should not change
diff kra_transport.key.before kra_transport.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA transport cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA audit signing cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_audit_signing | tee kra_audit_signing.crt.after

# cert should not change
diff kra_audit_signing.crt.before kra_audit_signing.crt.after

docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_audit_signing | tee kra_audit_signing.key.after

# key should not change
diff kra_audit_signing.key.before kra_audit_signing.key.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA audit signing cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    subsystem | tee subsystem.crt.after

# cert should not change
diff subsystem.crt.before subsystem.crt.after

docker exec kra pki \
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
    echo "FAIL: Check subsystem cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    sslserver | tee sslserver.crt.after

# cert should not change
diff sslserver.crt.before sslserver.crt.after

docker exec kra pki \
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
    echo "FAIL: Check SSL server cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-find
docker exec kra pki -n kraadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki -n caadmin ca-kraconnector-show | tee output
sed -n 's/\s*Host:\s\+\(\S\+\):.*/\1/p' output > actual
echo kra.example.com > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA from KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA from KRA container (rc=$_rc)" >&2
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

step "Check PKI server systemd journal in CA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in CA container (rc=$_rc)" >&2
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

step "Check PKI server systemd journal in KRA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-existing-certs-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-existing-certs-test PASSED ===="
