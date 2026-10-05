#!/bin/bash
# Generated TMT port of .github/workflows/kra-existing-ds-test.yml
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

step "Install CA"
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
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize CA admin in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file $SHARED/ca_signing.crt

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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server create
docker exec kra pki-server nss-create --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate cert request
docker exec kra pki-server cert-request \
    --subject "CN=DRM Storage Certificate" \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    kra_storage
docker exec kra cp /var/lib/pki/pki-tomcat/conf/certs/kra_storage.csr $SHARED
docker exec kra openssl req -text -noout -in $SHARED/kra_storage.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caStorageCert \
    --csr-file $SHARED/kra_storage.csr \
    --output-file $SHARED/kra_storage.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_storage.crt
docker exec kra cp $SHARED/kra_storage.crt /var/lib/pki/pki-tomcat/conf/certs

# import cert
docker exec kra pki-server cert-import kra_storage

# check original cert
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_storage | tee kra_storage.crt.before

# check original key
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_storage | tee kra_storage.key.before
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
# generate cert request
docker exec kra pki-server cert-request \
    --subject "CN=DRM Transport Certificate" \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    kra_transport
docker exec kra cp /var/lib/pki/pki-tomcat/conf/certs/kra_transport.csr $SHARED
docker exec ca openssl req -text -noout -in $SHARED/kra_transport.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caTransportCert \
    --csr-file $SHARED/kra_transport.csr \
    --output-file $SHARED/kra_transport.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_transport.crt
docker exec kra cp $SHARED/kra_transport.crt /var/lib/pki/pki-tomcat/conf/certs

# import cert
docker exec kra pki-server cert-import kra_transport

# check original cert
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_transport | tee kra_transport.crt.before

# check original key
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_transport | tee kra_transport.key.before
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
# generate cert request
docker exec kra pki-server cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    kra_audit_signing
docker exec kra cp /var/lib/pki/pki-tomcat/conf/certs/kra_audit_signing.csr $SHARED
docker exec ca openssl req -text -noout -in $SHARED/kra_audit_signing.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file $SHARED/kra_audit_signing.csr \
    --output-file $SHARED/kra_audit_signing.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_audit_signing.crt
docker exec kra cp $SHARED/kra_audit_signing.crt /var/lib/pki/pki-tomcat/conf/certs

# import cert
docker exec kra pki-server cert-import kra_audit_signing

# check original cert
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    kra_audit_signing | tee kra_audit_signing.crt.before

# check original key
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname kra_audit_signing | tee kra_audit_signing.key.before
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
# generate cert request
docker exec kra pki-server cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    subsystem
docker exec kra cp /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr $SHARED
docker exec ca openssl req -text -noout -in $SHARED/subsystem.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file $SHARED/subsystem.csr \
    --output-file $SHARED/subsystem.crt
docker exec ca openssl x509 -text -noout -in $SHARED/subsystem.crt
docker exec kra cp $SHARED/subsystem.crt /var/lib/pki/pki-tomcat/conf/certs

# import cert
docker exec kra pki-server cert-import subsystem

# check original cert
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    subsystem | tee subsystem.crt.before

# check original key
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname subsystem | tee subsystem.key.before
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
# generate cert request
docker exec kra pki-server cert-request \
    --subject "CN=kra.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    sslserver
docker exec kra cp /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr $SHARED
docker exec ca openssl req -text -noout -in $SHARED/sslserver.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file $SHARED/sslserver.csr \
    --output-file $SHARED/sslserver.crt
docker exec ca openssl x509 -text -noout -in $SHARED/sslserver.crt
docker exec kra cp $SHARED/sslserver.crt /var/lib/pki/pki-tomcat/conf/certs

# import cert
docker exec kra pki-server cert-import sslserver

# check original cert
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-show \
    sslserver | tee sslserver.crt.before

# check original key
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname sslserver | tee sslserver.key.before
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
# generate cert request
docker exec kra pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/kra_admin.csr
docker exec ca openssl req -text -noout -in $SHARED/kra_admin.csr

# issue cert
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file $SHARED/kra_admin.csr \
    --output-file $SHARED/kra_admin.crt
docker exec ca openssl x509 -text -noout -in $SHARED/kra_admin.crt

# import cert
docker exec kra pki nss-cert-import \
    --cert $SHARED/kra_admin.crt \
    kraadmin

# check original cert
docker exec kra pki nss-cert-show \
    kraadmin | tee kraadmin.crt.before

# check original key
docker exec kra pki nss-key-find \
    --nickname kraadmin | tee kraadmin.key.before
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA subsystem (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=krads.example.com \
    --network=example \
    --network-alias=krads.example.com \
    --password=Secret.123 \
    krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure connection to KRA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# store DS password
docker exec kra pki-server password-set \
    --password Secret.123 \
    internaldb

# configure DS connection params
docker exec kra pki-server kra-db-config-mod \
    --hostname krads.example.com \
    --port 3389 \
    --secure false \
    --auth BasicAuth \
    --bindDN "cn=Directory Manager" \
    --bindPWPrompt internaldb \
    --database userroot \
    --baseDN dc=kra,dc=pki,dc=example,dc=com \
    --multiSuffix false \
    --maxConns 15 \
    --minConns 3

# configure user/group subsystem to use DS
docker exec kra pki-server kra-config-set usrgrp.ldap internaldb
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure connection to KRA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check connection to KRA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check connection to KRA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize KRA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize KRA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-index-add -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Rebuild KRA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Rebuild KRA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-add \
    --full-name Administrator \
    --type adminType \
    --cert $SHARED/kra_admin.crt \
    kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-role-add kraadmin "Administrators"
docker exec kra pki-server kra-user-role-add kraadmin "Data Recovery Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://krads.example.com:3389 \
    -D pki_ds_setup=False \
    -D pki_security_domain_uri=https://ca.example.com:8443 \
    -D pki_issuing_ca_uri=https://ca.example.com:8443 \
    -D pki_admin_setup=False \
    -v

docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# KRA should join security domain in CA
cat > expected << EOF
securitydomain.host=ca.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=EXAMPLE
securitydomain.select=existing
EOF

docker exec kra pki-server kra-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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

step "Check KRA users"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-show kraadmin
docker exec kra pki-server kra-user-role-find kraadmin

docker exec kra pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec kra pki -n kraadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-connector-find | tee output

# KRA connector should be configured
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://kra.example.com:8443
  Nickname: subsystem
EOF

diff expected output

# REST API should return KRA connector info
docker exec ca pki -n caadmin ca-kraconnector-show | tee output
sed -n 's/\s*Host:\s\+\(\S\+\):.*/\1/p' output > actual
echo kra.example.com > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify cert key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-transport-export --output-file kra_transport.crt
docker exec ca CRMFPopClient \
    -d /root/.dogtag/nssdb \
    -p "" \
    -m ca.example.com:8080 \
    -f caDualCert \
    -n UID=testuser \
    -u testuser \
    -b kra_transport.crt \
    -v | tee output

REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)\s*$/\1/p" output)
echo "Request ID: $REQUEST_ID"

docker exec ca pki \
    -n caadmin \
    ca-cert-request-approve \
    $REQUEST_ID --force | tee output

CERT_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)\s*$/\1/p" output)
echo "Cert ID: $CERT_ID"

docker exec kra pki \
    -n kraadmin \
    kra-key-find \
    --owner UID=testuser | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify cert key archival (rc=$_rc)" >&2
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
    echo "==== kra-existing-ds-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-existing-ds-test PASSED ===="
