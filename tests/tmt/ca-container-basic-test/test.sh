#!/bin/bash
# Generated TMT port of .github/workflows/ca-container-basic-test.yml
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
    docker rm -f ca client ds 2>/dev/null || true
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
mkdir certs
mkdir conf
mkdir logs
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

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec client sed -n 's/^VERSION_ID=//p' /etc/os-release)
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
    -v $PWD/certs:/certs \
    -v $PWD/conf:/conf \
    -v $PWD/logs:/logs \
    -e PKI_DS_URL=ldap://ds.example.com:3389 \
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

step "Get Tomcat flavor"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TOMCAT_FLAVOR=$(docker exec ca test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
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

step "Check conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l conf \
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
drwxrwx--- runner ca
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
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
drwxrwx--- runner ca
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
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
    echo "FAIL: Check conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check conf/ca dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l conf/ca \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
        -e '/^\S* *\S* *\S* *CS.cfg.bak /d' \
    | tee output

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- runner CS.cfg
-rw-rw---- runner adminCert.profile
drwxrwxrwx runner archives
-rw-rw---- runner caAuditSigningCert.profile
-rw-rw---- runner caCert.profile
-rw-rw---- runner caOCSPCert.profile
drwxrwx--- runner emails
-rw-rw---- runner flatfile.txt
drwxrwx--- runner profiles
-rw-rw---- runner proxy.conf
-rw-rw---- runner registry.cfg
-rw-rw---- runner serverCert.profile
-rw-rw---- runner subsystemCert.profile
EOF

cat > expected_new << EOF
-rw-rw---- runner CS.cfg
-rw-rw---- runner adminCert.profile
drwxrwxrwx runner archives
-rw-rw---- runner caAuditSigningCert.profile
-rw-rw---- runner caCert.profile
-rw-rw---- runner caOCSPCert.profile
drwxrwx--- runner emails
-rw-rw---- runner flatfile.txt
drwxrwx--- runner profiles
-rw-rw---- runner proxy.conf
-rw-rw---- runner registry.cfg
-rw-rw---- runner serverCert.profile
-rw-rw---- runner subsystemCert.profile
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conf/ca dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
ls -l logs \
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
drwxrwx--- runner ca
-rw-rw---- runner localhost.$DATE.log
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
ls -l logs \
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
drwxrwx--- runner ca
-rw-rw-rw- runner localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- runner backup
drwxrwx--- runner ca
-rw-rw-rw- runner localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/ca_signing.crt \
    ca_signing

docker exec client pki nss-cert-import \
    --cert $SHARED/conf/certs/ca_signing.crt \
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

step "Import subsystem cert into CA database"
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
    echo "FAIL: Import subsystem cert into CA database (rc=$_rc)" >&2
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

step "Check certs in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    ca-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CA admin user
docker exec ca pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --cert /tmp/admin.crt \
    admin

# add CA admin user into CA groups
docker exec ca pki-server ca-user-role-add admin "Administrators"
docker exec ca pki-server ca-user-role-add admin "Certificate Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user (rc=$_rc)" >&2
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

step "Check cert enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec client pki \
    -U https://ca.example.com:8443 \
    client-cert-request \
    uid=testuser | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

# issue cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-cert-request-approve \
    $REQUEST_ID \
    --force
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment (rc=$_rc)" >&2
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

step "Check CA admin user again"
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
    echo "FAIL: Check CA admin user again (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-container-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-container-basic-test PASSED ===="
