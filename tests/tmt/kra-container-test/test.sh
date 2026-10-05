#!/bin/bash
# Generated TMT port of .github/workflows/kra-container-test.yml
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
    docker rm -f ca cads client kra krads 2>/dev/null || true
    docker volume rm ds-data 2>/dev/null || true
    docker network rm example 2>/dev/null || true
}
trap cleanup EXIT

step() { echo; echo "==== $* ===="; }
GHA_FAILED=0

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v podman-docker >/dev/null 2>&1 || dnf install -y podman-docker 2>/dev/null || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

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

step "Create shared folders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir -p ca/certs
mkdir -p ca/conf
mkdir -p ca/logs
mkdir -p kra/certs
mkdir -p kra/conf
mkdir -p kra/logs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create shared folders (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=client.example.com \
    --network=example \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install ASN.1 parser"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y dumpasn1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install ASN.1 parser (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name ca \
    --hostname ca.example.com \
    --network example \
    --network-alias ca.example.com \
    -v $PWD/ca/certs:/certs \
    -v $PWD/ca/conf:/conf \
    -v $PWD/ca/logs:/logs \
    -e PKI_DS_URL=ldap://cads.example.com:3389 \
    -e PKI_DS_PASSWORD=Secret.123 \
    --detach \
    pki-ca

# wait for CA to start
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker cp ca:ca_signing.crt .

docker exec client pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec client pki \
    -U https://ca.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA info (rc=$_rc)" >&2
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

step "Initialize CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-db-init -v
docker exec ca pki-server ca-db-index-add -v
docker exec ca pki-server ca-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/ca_signing.crt \
    ca_signing

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/ca_signing.crt \
    --csr /conf/certs/ca_signing.csr \
    --profile /usr/share/pki/ca/conf/caCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA OCSP signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/ca_ocsp_signing.crt \
    ca_ocsp_signing

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/ca_ocsp_signing.crt \
    --csr /conf/certs/ca_ocsp_signing.csr \
    --profile /usr/share/pki/ca/conf/caOCSPCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA OCSP signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA subsystem cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/subsystem.crt \
    subsystem

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/subsystem.crt \
    --csr /conf/certs/subsystem.csr \
    --profile /usr/share/pki/ca/conf/rsaSubsystemCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA subsystem cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import SSL server cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/sslserver.crt \
    sslserver

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/sslserver.crt \
    --csr /conf/certs/sslserver.csr \
    --profile /usr/share/pki/ca/conf/rsaServerCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec client pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/admin.csr

docker cp admin.csr ca:.

# issue cert
docker exec ca pki-server ca-cert-create \
    --csr admin.csr \
    --profile /usr/share/pki/ca/conf/rsaAdminCert.profile \
    --cert /tmp/admin.crt \
    --import-cert

docker cp ca:/tmp/admin.crt .

# import cert
docker exec client pki nss-cert-import \
    --cert $SHARED/admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --cert /tmp/admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user into CA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-role-add admin "Administrators"
docker exec ca pki-server ca-user-role-add admin "Certificate Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user into CA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=DRM Storage Certificate" \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --csr $SHARED/kra/certs/kra_storage.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/kra_storage.csr \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --cert $SHARED/kra/certs/kra_storage.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/kra_storage.crt \
    kra_storage

docker exec client pki nss-cert-show kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=DRM Transport Certificate" \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    --csr $SHARED/kra/certs/kra_transport.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/kra_transport.csr \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    --cert $SHARED/kra/certs/kra_transport.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/kra_transport.crt \
    kra_transport

docker exec client pki nss-cert-show kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/kra/certs/subsystem.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/kra/certs/subsystem.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/subsystem.crt \
    subsystem

docker exec client pki nss-cert-show subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=kra.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/kra/certs/sslserver.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/kra/certs/sslserver.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/sslserver.crt \
    sslserver

docker exec client pki nss-cert-show sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare KRA certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec client cp $SHARED/ca/conf/certs/ca_signing.crt $SHARED/kra/certs

docker exec client pki nss-cert-find

# export KRA system certs and keys
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123 \
    kra_storage \
    kra_transport \
    subsystem \
    sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123

ls -la kra/certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare KRA certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name kra \
    --hostname kra.example.com \
    --network example \
    --network-alias kra.example.com \
    -v $PWD/kra/certs:/certs \
    -v $PWD/kra/conf:/conf \
    -v $PWD/kra/logs:/logs \
    -e PKI_DS_URL=ldap://krads.example.com:3389 \
    -e PKI_DS_PASSWORD=Secret.123 \
    --detach \
    pki-kra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for KRA container to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://kra.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for KRA container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec kra sed -n 's/^VERSION_ID=//p' /etc/os-release)
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

step "Get Tomcat flavor"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TOMCAT_FLAVOR=$(docker exec kra test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
echo "TOMCAT_FLAVOR=$TOMCAT_FLAVOR" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Tomcat flavor (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Check KRA conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l kra/conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- runner Catalina
drwxrwx--- runner alias
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
drwxrwx--- runner kra
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- runner password.conf
-rw-rw---- runner server.xml
-rw-rw---- runner serverCertNick.conf
-rw-rw---- runner tomcat.conf
lrwxrwxrwx runner web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- runner Catalina
drwxrwx--- runner alias
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
drwxrwx--- runner kra
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- runner password.conf
-rw-rw---- runner server.xml
-rw-rw---- runner serverCertNick.conf
-rw-rw---- runner tomcat.conf
lrwxrwxrwx runner web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA conf/kra dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l kra/conf/kra \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
        -e '/^\S* *\S* *CS.cfg.bak /d' \
    | tee output

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- runner CS.cfg
drwxrwxrwx runner archives
-rw-rw---- runner registry.cfg
EOF

cat > expected_new << EOF
-rw-rw---- runner CS.cfg
drwxrwxrwx runner archives
-rw-rw---- runner registry.cfg
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA conf/kra dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
ls -l kra/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected << EOF
drwxrwx--- runner backup
drwxrwx--- runner kra
-rw-rw---- runner localhost.$DATE.log
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
ls -l kra/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- runner backup
drwxrwx--- runner kra
-rw-rw-rw- runner localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- runner backup
drwxrwx--- runner kra
-rw-rw-rw- runner localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA info (rc=$_rc)" >&2
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

step "Set up KRA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-init -v
docker exec kra pki-server kra-db-index-add -v
docker exec kra pki-server kra-db-index-rebuild  -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp admin.crt kra:.

docker exec kra pki-server kra-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA admin user into KRA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-role-add admin "Administrators"
docker exec kra pki-server kra-user-role-add admin "Data Recovery Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA admin user into KRA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA subsystem user in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cp ca/conf/certs/subsystem.crt kra/conf/certs/ca_subsystem.crt
docker exec kra pki-server kra-user-add \
    --full-name CA-ca.example.com-8443 \
    --type agentType \
    --cert /conf/certs/ca_subsystem.crt \
    CA-ca.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA subsystem user in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to CA subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-role-add CA-ca.example.com-8443 "Trusted Managers"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to CA subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp kra/certs/kra_transport.crt ca:.

docker exec ca pki-server ca-connector-add \
   --url https://kra.example.com:8443 \
   --nickname subsystem \
   --transport-cert kra_transport.crt \
   KRA

TRANSPORT_CERT=$(openssl x509 \
    -in kra/certs/kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec ca pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be configured
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=kra.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart ca
sleep 10

docker network reload --all

# wait for CA to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Request cert with key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate key and cert request
# https://github.com/dogtagpki/pki/wiki/Generating-Certificate-Request-with-PKI-NSS
docker exec client pki \
    nss-cert-request \
    --type crmf \
    --subject CN=server.example.com \
    --subjectAltName "critical, DNS:www.example.com" \
    --transport kra_transport \
    --csr $SHARED/server.csr

# check PEM CSR
cat server.csr

# convert CSR into DER
sed -e '/^-----/d' server.csr | tr -d '\r\n' | tee server.b64
base64 -d server.b64 > server.der

# display ASN.1 CSR
docker exec client dumpasn1 $SHARED/server.der
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Request cert with key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue cert with key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# issue cert
# https://github.com/dogtagpki/pki/wiki/Issuing-Certificates
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-cert-issue \
    --request-type crmf \
    --profile caServerCert \
    --subject CN=server.example.com \
    --csr-file $SHARED/server.csr \
    --output-file server.crt

docker exec client openssl x509 -text -noout -in server.crt

# import cert into NSS database
docker exec client pki nss-cert-import --cert server.crt server

# the cert should match the key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec client pki nss-cert-show server | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue cert with key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find archived key by owner
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-key-find --owner CN=server.example.com | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > key.id

DEC_KEY_ID=$(python -c "print(int('$KEY_ID', 16))")
echo "Dec Key ID: $DEC_KEY_ID"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key retrieval"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

BASE64_CERT=$(docker exec client pki nss-cert-export --format DER server | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

cat > request.json <<EOF
{
  "ClassName" : "com.netscape.certsrv.key.KeyRecoveryRequest",
  "Attributes" : {
    "Attribute" : [ {
      "name" : "keyId",
      "value" : "$KEY_ID"
    }, {
      "name" : "certificate",
      "value" : "$BASE64_CERT"
    }, {
      "name" : "passphrase",
      "value" : "Secret.123"
    } ]
  }
}
EOF

docker cp request.json client:.

# retrieve archived cert and key into PKCS #12 file
# https://github.com/dogtagpki/pki/wiki/Retrieving-Archived-Key
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-key-retrieve \
    --input request.json \
    --output-data archived.p12

# import PKCS #12 file into NSS database
docker exec client pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 archived.p12 \
    --password Secret.123

docker exec client pki -d nssdb nss-cert-find

# remove archived cert from NSS database
docker exec client pki -d nssdb nss-cert-del CN=server.example.com

# import original cert into NSS database
docker exec client pki -d nssdb nss-cert-import --cert server.crt server

# the original cert should match the archived key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec client pki -d nssdb nss-cert-show server | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key retrieval (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart kra
sleep 10

docker network reload --all

# wait for KRA to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://kra.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin user again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin user again (rc=$_rc)" >&2
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

step "Check CA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ca 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec krads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs kra 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check client container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-container-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-container-test PASSED ===="
