#!/bin/bash
# Generated TMT port of .github/workflows/ca-container-existing-config-test.yml
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
    docker rm -f ca client ds pki 2>/dev/null || true
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
    --hostname=ca.example.com \
    --network=example \
    --network-alias=ca.example.com \
    pki
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_ds_password=Secret.123 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
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
    --network-alias=client.example.com \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker cp pki:ca_signing.crt .

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

step "Check CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp pki:/root/.dogtag/pki-tomcat/ca_admin_cert.p12 .

docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server stop --wait
docker network disconnect example pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir certs

# export system certs and keys
docker exec pki pki \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    pkcs12-export \
    --pkcs12 $SHARED/certs/server.p12 \
    --password Secret.123 \
    ca_signing \
    ca_ocsp_signing \
    ca_audit_signing \
    subsystem \
    sslserver

docker exec pki pki pkcs12-cert-find \
    --pkcs12 $SHARED/certs/server.p12 \
    --password Secret.123

# export system cert requests
docker exec pki cp \
    /var/lib/pki/pki-tomcat/conf/certs/ca_signing.csr \
    $SHARED/certs/ca_signing.csr
docker exec pki cp \
    /var/lib/pki/pki-tomcat/conf/certs/ca_ocsp_signing.csr \
    $SHARED/certs/ca_ocsp_signing.csr
docker exec pki cp \
    /var/lib/pki/pki-tomcat/conf/certs/ca_audit_signing.csr \
    $SHARED/certs/audit_signing.csr
docker exec pki cp \
    /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr \
    $SHARED/certs/subsystem.csr
docker exec pki cp \
    /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr \
    $SHARED/certs/sslserver.csr

ls -la certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export config files"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp pki:/etc/pki/pki-tomcat conf

ls -la conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export config files (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export log files"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp pki:/var/log/pki/pki-tomcat logs

ls -la logs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export log files (rc=$_rc)" >&2
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
    -v $PWD/certs:/certs \
    -v $PWD/conf:/conf \
    -v $PWD/logs:/logs \
    -e PKI_DS_URL=ldap://ds.example.com:3389 \
    -e PKI_DS_PASSWORD=Secret.123 \
    -e PKI_CA_SIGNING_NICKNAME=ca_signing \
    -e PKI_OCSP_SIGNING_NICKNAME=ca_ocsp_signing \
    -e PKI_AUDIT_SIGNING_NICKNAME=ca_audit_signing \
    -e PKI_SUBSYSTEM_NICKNAME=subsystem \
    -e PKI_SSLSERVER_NICKNAME=sslserver \
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
TOMCAT_FLAVOR=$(docker exec pki test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
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
docker exec ca ls -l /conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by root group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- root Catalina
drwxrwx--- root alias
drwxrwx--- root ca
-rw-r--r-- root catalina.policy
lrwxrwxrwx root catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- root certs
lrwxrwxrwx root context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx root logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- root password.conf
-rw-rw---- root server.xml
-rw-rw---- root serverCertNick.conf
-rw-rw---- root tomcat.conf
lrwxrwxrwx root web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- root Catalina
drwxrwx--- root alias
drwxrwx--- root ca
-rw-r--r-- root catalina.policy
lrwxrwxrwx root catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- root certs
lrwxrwxrwx root context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx root logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- root password.conf
-rw-rw---- root server.xml
-rw-rw---- root serverCertNick.conf
-rw-rw---- root tomcat.conf
lrwxrwxrwx root web.xml -> /etc/tomcat/web.xml
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
docker exec ca ls -l /conf/ca \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
        -e '/^\S* *\S* *\S* *CS.cfg.bak /d' \
    | tee output

# everything should be owned by root group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- root CS.cfg
-rw-rw---- root adminCert.profile
drwxr-xr-x root archives
-rw-rw---- root caAuditSigningCert.profile
-rw-rw---- root caCert.profile
-rw-rw---- root caOCSPCert.profile
drwxrwx--- root emails
-rw-rw---- root flatfile.txt
drwxrwx--- root profiles
-rw-rw---- root proxy.conf
-rw-rw---- root registry.cfg
-rw-rw---- root serverCert.profile
-rw-rw---- root subsystemCert.profile
EOF

cat > expected_new << EOF
-rw-rw---- root CS.cfg
-rw-rw---- root adminCert.profile
drwxr-xr-x root archives
-rw-rw---- root caAuditSigningCert.profile
-rw-rw---- root caCert.profile
-rw-rw---- root caOCSPCert.profile
drwxrwx--- root emails
-rw-rw---- root flatfile.txt
drwxrwx--- root profiles
-rw-rw---- root proxy.conf
-rw-rw---- root registry.cfg
-rw-rw---- root serverCert.profile
-rw-rw---- root subsystemCert.profile
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
docker exec ca ls -l /logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by root group
# TODO: review owners/permissions
cat > expected << EOF
drwxrwx--- root backup
drwxrwx--- root ca
-rw-rw---- root localhost.$DATE.log
-rw-r--r-- root localhost_access_log.$DATE.txt
drwxrwx--- root pki
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
docker exec ca ls -l /logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by root group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- root backup
drwxrwx--- root ca
-rw-r--r-- root localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- root backup
drwxrwx--- root ca
-rw-r----- root localhost_access_log.$DATE.txt
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

step "Check CA admin user again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
#TODO: OCSPServlet fails since AuthorityMonitor is disabled in container
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    --ignore-cert-status OCSP_SERVER_ERROR \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    --ignore-cert-status OCSP_SERVER_ERROR \
    client-cert-request \
    uid=testuser | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    --ignore-cert-status OCSP_SERVER_ERROR \
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

step "Check CA container debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-container-existing-config-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-container-existing-config-test PASSED ===="
