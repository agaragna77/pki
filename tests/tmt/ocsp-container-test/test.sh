#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-container-test.yml
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
    docker rm -f ca cads client ocsp ocspds 2>/dev/null || true
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
# Packages needed: libxml2-utils podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v libxml2-utils >/dev/null 2>&1 || dnf install -y libxml2-utils 2>/dev/null || true
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
mkdir -p ocsp/certs
mkdir -p ocsp/conf
mkdir -p ocsp/logs
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
    --hostname=ds.example.com \
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

step "Create OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --csr $SHARED/ocsp/certs/ocsp_signing.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/ocsp/certs/ocsp_signing.csr \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --cert $SHARED/ocsp/certs/ocsp_signing.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ocsp/certs/ocsp_signing.crt \
    ocsp_signing

docker exec client pki nss-cert-show ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create OCSP subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/ocsp/certs/subsystem.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/ocsp/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/ocsp/certs/subsystem.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ocsp/certs/subsystem.crt \
    subsystem

docker exec client pki nss-cert-show subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create OCSP subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create OCSP SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=ocsp.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/ocsp/certs/sslserver.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/ocsp/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/ocsp/certs/sslserver.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ocsp/certs/sslserver.crt \
    sslserver

docker exec client pki nss-cert-show sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create OCSP SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare OCSP certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec client cp $SHARED/ca/conf/certs/ca_signing.crt $SHARED/ocsp/certs

docker exec client pki nss-cert-find

# export OCSP system certs and keys
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/ocsp/certs/server.p12 \
    --password Secret.123 \
    ocsp_signing \
    subsystem \
    sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/ocsp/certs/server.p12 \
    --password Secret.123

ls -la ocsp/certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare OCSP certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name ocsp \
    --hostname ocsp.example.com \
    --network example \
    --network-alias ocsp.example.com \
    -v $PWD/ocsp/certs:/certs \
    -v $PWD/ocsp/conf:/conf \
    -v $PWD/ocsp/logs:/logs \
    -e PKI_DS_URL=ldap://ocspds.example.com:3389 \
    -e PKI_DS_PASSWORD=Secret.123 \
    --detach \
    pki-ocsp
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for OCSP container to start"
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
    https://ocsp.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for OCSP container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec ocsp sed -n 's/^VERSION_ID=//p' /etc/os-release)
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
TOMCAT_FLAVOR=$(docker exec ocsp test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
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

step "Check OCSP conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l ocsp/conf \
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
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- runner ocsp
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
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- runner ocsp
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
    echo "FAIL: Check OCSP conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP conf/ocsp dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l ocsp/conf/ocsp \
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
    echo "FAIL: Check OCSP conf/ocsp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
ls -l ocsp/logs \
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
-rw-rw---- runner localhost.$DATE.log
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner ocsp
drwxrwx--- runner pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
ls -l ocsp/logs \
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
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner ocsp
EOF

cat > expected_new << EOF
drwxrwx--- runner backup
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner ocsp
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP info (rc=$_rc)" >&2
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
    --hostname=ds.example.com \
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

step "Set up OCSP database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server ocsp-db-init -v
docker exec ocsp pki-server ocsp-db-index-add -v
docker exec ocsp pki-server ocsp-db-index-rebuild  -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add OCSP admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp admin.crt ocsp:.

docker exec ocsp pki-server ocsp-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add OCSP admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add OCSP admin user into OCSP groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server ocsp-user-role-add admin "Administrators"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add OCSP admin user into OCSP groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n admin \
    ocsp-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA subsystem user in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cp ca/conf/certs/subsystem.crt ocsp/conf/certs/ca_subsystem.crt
docker exec ocsp pki-server ocsp-user-add \
    --full-name CA-ca.example.com-8443 \
    --type agentType \
    --cert /conf/certs/ca_subsystem.crt \
    CA-ca.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA subsystem user in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to CA subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server ocsp-user-role-add CA-ca.example.com-8443 "Trusted Managers"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to CA subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CRL issuing point"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# convert CA signing cert into PKCS #7 chain
docker exec ocsp pki pkcs7-cert-import --pkcs7 /certs/ca_signing.p7 --input-file /certs/ca_signing.crt
docker exec ocsp pki pkcs7-cert-find --pkcs7 /certs/ca_signing.p7

# create CRL issuing point with the PKCS #7 chain
docker exec ocsp pki-server ocsp-crl-issuingpoint-add --cert-chain /certs/ca_signing.p7
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CRL issuing point (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure OCSP connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure OCSP publisher
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.enableClientAuth true
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.host ocsp.example.com
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.nickName subsystem
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.path /ocsp/agent/ocsp/addCRL
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.pluginName OCSPPublisher
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.port 8443

# configure CRL publishing rule
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.enable true
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.mapper NoMap
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.pluginName Rule
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.publisher OCSPPublisher
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.type crl

# enable CRL publishing
docker exec ca pki-server ca-config-set ca.publish.enable true

# set buffer size to 0 so that revocation will take effect immediately
docker exec ca pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec ca pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure OCSP connector in CA (rc=$_rc)" >&2
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

step "Create user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    client-cert-request \
    uid=testuser | tee output

REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" output)
echo "Request ID: $REQUEST_ID"

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-cert-request-approve \
    --force \
    $REQUEST_ID | tee output

CERT_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" output)
echo "Cert ID: $CERT_ID"
echo "$CERT_ID" > cert.id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with initial CRL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

# export admin cert and key
docker exec client pki pkcs12-export \
    --pkcs12 admin.p12 \
    --password Secret.123 \
    admin

# force CRL update
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-crl-update

# wait for CRL update
sleep 10

# check cert status using OCSPClient
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# cert status should be good
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Good > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with initial CRL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

# place cert on-hold
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-cert-hold \
    --force \
    $CERT_ID | tee output

# cert should be revoked
echo "REVOKED" > expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual

# force CRL update
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-crl-update

# wait for CRL update
sleep 10

# check cert status using OCSPClient
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# cert status should be revoked
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Revoked > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with after unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

# place cert off-hold
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-cert-release-hold \
    --force \
    $CERT_ID | tee output

# cert should be valid
echo "VALID" > expected
sed -n "s/^\s*Status:\s*\(\S*\)$/\1/p" output > actual
diff expected actual

# force CRL update
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-crl-update

# wait for CRL update
sleep 10

# check cert status using OCSPClient
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# cert status should be good
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Good > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with after unrevocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart ocsp
sleep 10

docker network reload --all

# wait for OCSP to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ocsp.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP admin user again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n admin \
    ocsp-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP admin user again (rc=$_rc)" >&2
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

step "Check OCSP container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ocsp 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP debug logs (rc=$_rc)" >&2
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
    echo "==== ocsp-container-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-container-test PASSED ===="
