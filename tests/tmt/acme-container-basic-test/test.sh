#!/bin/bash
# Generated TMT port of .github/workflows/acme-container-basic-test.yml
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
    docker rm -f acme client 2>/dev/null || true
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

step "Retrieve ACME images"
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
    echo "FAIL: Retrieve ACME images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load ACME images"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker load from cache — images built locally by prepare
echo "Images already available (built by TMT prepare)"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Load ACME images (rc=$_rc)" >&2
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

step "Install dependencies in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y certbot
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create shared folders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir certs
mkdir metadata
mkdir database
mkdir issuer
mkdir realm
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

step "Set up ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name acme \
    --hostname acme.example.com \
    --network example \
    --network-alias acme.example.com \
    -v $PWD/certs:/certs \
    -v $PWD/metadata:/metadata \
    -v $PWD/database:/database \
    -v $PWD/issuer:/issuer \
    -v $PWD/realm:/realm \
    -v $PWD/conf:/conf \
    -v $PWD/logs:/logs \
    --detach \
    pki-acme

# wait for ACME to start
docker exec client curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    http://acme.example.com:8080/acme/directory
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec acme sed -n 's/^VERSION_ID=//p' /etc/os-release)
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
TOMCAT_FLAVOR=$(docker exec acme test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
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
docker exec acme ls -l conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by root group (GID=0)
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- root Catalina
drwxrwx--- root acme
drwxrwx--- root alias
-rw-rw---- root catalina.policy
lrwxrwxrwx root catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- root certs
lrwxrwxrwx root context.xml -> /etc/tomcat/context.xml
-rw-rw---- root jss.conf
lrwxrwxrwx root logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- root password.conf
-rw-rw---- root server.xml
-rw-rw---- root tomcat.conf
lrwxrwxrwx root web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- root Catalina
drwxrwx--- root acme
drwxrwx--- root alias
-rw-rw---- root catalina.policy
lrwxrwxrwx root catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- root certs
lrwxrwxrwx root context.xml -> /etc/tomcat/context.xml
-rw-rw---- root jss.conf
lrwxrwxrwx root logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- root password.conf
-rw-rw---- root server.xml
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

step "Check conf/acme dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme ls -l conf/acme \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by root group (GID=0)
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- root database.conf
-rw-rw---- root issuer.conf
-rw-rw---- root realm.conf
EOF

cat > expected_new << EOF
-rw-rw---- root database.conf
-rw-rw---- root issuer.conf
-rw-rw---- root realm.conf
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conf/acme dir (rc=$_rc)" >&2
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

# everything should be owned by root group (GID=0)
# TODO: review owners/permissions
cat > expected << EOF
-rw-rw-rw- root localhost.$DATE.log
-rw-rw-rw- root localhost_access_log.$DATE.txt
drwxrwxrwx root pki
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

# everything should be owned by root group (GID=0)
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw-rw- root localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
-rw-rw-rw- root localhost_access_log.$DATE.txt
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

step "Install CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pki \
    -d /conf/alias \
    -f /conf/password.conf \
    nss-cert-export \
    --output-file /conf/certs/ca_signing.crt \
    ca_signing

docker exec client pki nss-cert-import \
    --cert $SHARED/conf/certs/ca_signing.crt \
    --trust CT,C,C \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://acme.example.com:8443 \
    acme-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://acme.example.com:8080/acme/directory \
    --email user1@example.com \
    --agree-tos \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot certonly \
    --server http://acme.example.com:8080/acme/directory \
    -d client.example.com \
    --key-type rsa \
    --standalone \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl x509 \
    -text \
    -noout \
    -in /etc/letsencrypt/live/client.example.com/fullchain.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Renew client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot renew \
    --server http://acme.example.com:8080/acme/directory \
    --cert-name client.example.com \
    --force-renewal \
    --no-random-sleep-on-renew \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Renew client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot update_account \
    --server http://acme.example.com:8080/acme/directory \
    --email user2@example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot unregister \
    --server http://acme.example.com:8080/acme/directory \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart acme
sleep 5

# wait for ACME to restart
docker exec client curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    http://acme.example.com:8080/acme/directory
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME status again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://acme.example.com:8443 \
    acme-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME status again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs acme 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certbot logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec client cat /var/log/letsencrypt/letsencrypt.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certbot logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check client container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs client 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== acme-container-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-container-basic-test PASSED ===="
