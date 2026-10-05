#!/bin/bash
# Generated TMT port of .github/workflows/tps-basic-test.yml
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

step "Check pki tps CLI help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki tps
docker exec pki pki tps --help

docker exec pki pki tps-token-find --help
docker exec pki pki tps-token-show --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki tps CLI help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/tks.cfg \
    -s TKS \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/tps.cfg \
    -s TPS \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    -D pki_authdb_url=ldap://ds.example.com:3389 \
    -D pki_enable_server_side_keygen=True \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server base dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server base dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server conf dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
drwxrwx--- pkiuser pkiuser ca
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
drwxrwx--- pkiuser pkiuser tks
-rw-rw---- pkiuser pkiuser tomcat.conf
drwxrwx--- pkiuser pkiuser tps
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
drwxrwx--- pkiuser pkiuser ca
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
drwxrwx--- pkiuser pkiuser tks
-rw-rw---- pkiuser pkiuser tomcat.conf
drwxrwx--- pkiuser pkiuser tps
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server conf dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check server.xml"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check server.xml (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server conf/alias dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat/alias \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
-rw------- pkiuser pkiuser ca.crt
-rw------- pkiuser pkiuser cert9.db
-rw------- pkiuser pkiuser key4.db
-rw------- pkiuser pkiuser pkcs11.txt
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server conf/alias dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server conf/Catalina/localhost dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat/Catalina/localhost \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
-rw-rw---- pkiuser pkiuser ROOT.xml
-rw-rw---- pkiuser pkiuser ca.xml
-rw-rw---- pkiuser pkiuser kra.xml
-rw-rw---- pkiuser pkiuser pki.xml
lrwxrwxrwx pkiuser pkiuser rewrite.config -> /usr/share/pki/server/conf/Catalina/localhost/rewrite.config
-rw-rw---- pkiuser pkiuser tks.xml
-rw-rw---- pkiuser pkiuser tps.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server conf/Catalina/localhost dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS base dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat/tps \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/alias
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/tps
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/tps
lrwxrwxrwx pkiuser pkiuser registry -> /etc/sysconfig/pki/tomcat/pki-tomcat
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/alias
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/tps
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/tps
lrwxrwxrwx pkiuser pkiuser registry -> /etc/sysconfig/pki/tomcat/pki-tomcat
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS base dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS conf dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat/conf/tps \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser phoneHome.xml
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

cat > expected_new << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser phoneHome.xml
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server status | tee output

# CA should be a domain manager, but KRA, TKS, TPS should not
echo "True" > expected
echo "False" >> expected
echo "False" >> expected
echo "False" >> expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export subsystem \
    --cert-file subsystem.crt
docker exec pki openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr
docker exec pki openssl x509 -text -noout -in subsystem.crt
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
docker exec pki pki-server cert-export sslserver \
    --cert-file sslserver.crt
docker exec pki openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr
docker exec pki openssl x509 -text -noout -in sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS admin cert (rc=$_rc)" >&2
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
    docker exec pki pki-healthcheck \
        --failures-only \
        --debug \
        > >(tee stdout) 2> >(tee stderr >&2)
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

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki pki -n caadmin tps-user-show tpsadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check connectors in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server tps-connector-find | tee output

cat > expected << EOF
  Connector ID: ca1
  Type: CA
  Enabled: true
  URL: https://pki.example.com:8443
  Nickname: subsystem

  Connector ID: kra1
  Type: KRA
  Enabled: true
  URL: https://pki.example.com:8443
  Nickname: subsystem

  Connector ID: tks1
  Type: TKS
  Enabled: true
  URL: https://pki.example.com:8443
  Nickname: subsystem
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check connectors in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS authentication and misc cfg settings"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import sample TPS users
docker exec pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/tps/auth/ds/create.ldif
docker exec pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/tps/auth/ds/example.ldif

# configure TPS to use the sample TPS users
docker exec pki pki-server tps-config-set \
    auths.instance.ldap1.ldap.basedn \
    ou=people,dc=example,dc=com

# configure TPS to allow tpsclient tests to work
docker exec pki pki-server tps-config-set \
    channel.scp01.no.le.byte true

# reset PIN_RESET after PIN reset
docker exec pki pki-server tps-config-set \
    tokendb.defaultPolicy \
    "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=YES"

# restart TPS subsystem
docker exec pki pki-server tps-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS authentication and misc cfg settings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki tps-client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > script << EOF
op=help

op=var_set name=ra_host value=pki.example.com
op=var_set name=ra_port value=8080
op=var_set name=ra_uri value=/tps/tps
op=var_list

op=token_set cuid=ef890c6baf38e41a5cac
op=token_set msn=01020304
op=token_set app_ver=6FBBC105
op=token_set key_info=0101
op=token_set major_ver=0
op=token_set minor_ver=0
op=token_set auth_key=404142434445464748494a4b4c4d4e4f
op=token_set mac_key=404142434445464748494a4b4c4d4e4f
op=token_set kek_key=404142434445464748494a4b4c4d4e4f
op=token_status

op=exit
EOF

cat script | docker exec -i pki pki tps-client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki tps-client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tpsclient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# ignore return code
cat script | docker exec -i pki tpsclient || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tpsclient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add token for testuser1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
hexdump -v -n "10" -e '1/1 "%02x"' /dev/urandom > cuid
CUID=$(cat cuid)

# allow one-time PIN reset
docker exec pki pki -n caadmin tps-token-add \
    --policy "PIN_RESET=YES" \
    $CUID | tee output

echo "UNFORMATTED" > expected
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add token for testuser1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Format testuser1 token using pki tps-client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-format \
    --user=testuser1 \
    --password=Secret.123 \
    $CUID

echo "FORMATTED" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Format testuser1 token using pki tps-client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll testuser1 token using pki tps-client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-enroll \
    --user=testuser1 \
    --password=Secret.123 \
    $CUID

echo "ACTIVE" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll testuser1 token using pki tps-client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Reset PIN for testuser1 token using pki tps-client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-pin-reset \
    --user=testuser1 \
    --password=Secret.123 \
    --new-password=Secret.456 \
    $CUID

# TODO: validate new PIN

# PIN_RESET should become NO
echo "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=YES;RENEW_KEEP_OLD_ENC_CERTS=YES" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Policy:\s\+\(\S\+\)\s*/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Reset PIN for testuser1 token using pki tps-client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Find testuser1 key in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid | tr [:lower:] [:upper:])
USER="testuser1"
echo $CUID:$USER > expected
docker exec pki pki -n caadmin kra-key-find --owner $CUID:$USER | tee output
sed -n 's/\s*Owner:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find testuser1 key in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add token for testuser2"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
hexdump -v -n "10" -e '1/1 "%02x"' /dev/urandom > cuid
CUID=$(cat cuid)

# allow one-time PIN reset
docker exec pki pki -n caadmin tps-token-add \
    --policy "PIN_RESET=YES" \
    $CUID | tee output

echo "UNFORMATTED" > expected
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add token for testuser2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Format testuser2 token using tpsclient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-format \
    --client=tpsclient \
    --user=testuser2 \
    --password=Secret.123 \
    $CUID

echo "FORMATTED" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Format testuser2 token using tpsclient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll testuser2 token using tpsclient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-enroll \
    --client=tpsclient \
    --user=testuser2 \
    --password=Secret.123 \
    $CUID

echo "ACTIVE" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual

docker exec pki pki -n caadmin tps-cert-find --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll testuser2 token using tpsclient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Reset PIN for testuser2 token using tpsclient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec pki /usr/share/pki/tps/bin/pki-tps-pin-reset \
    --client=tpsclient \
    --user=testuser2 \
    --password=Secret.123 \
    --new-password=Secret.456 \
    $CUID

# TODO: validate new PIN

# PIN_RESET should become NO
echo "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=YES;RENEW_KEEP_OLD_ENC_CERTS=YES" > expected
docker exec pki pki -n caadmin tps-token-show $CUID | tee output
sed -n 's/\s*Policy:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Reset PIN for testuser2 token using tpsclient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Find testuser2 key in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid | tr [:lower:] [:upper:])
USER="testuser2"
echo $CUID:$USER > expected
docker exec pki pki -n caadmin kra-key-find --owner $CUID:$USER | tee output
sed -n 's/\s*Owner:\s\+\(\S\+\)\s*/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find testuser2 key in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy \
    -s TPS \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s TKS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA (rc=$_rc)" >&2
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

step "Check PKI server base dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
EOF


diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server base dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server conf dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
drwxrwx--- pkiuser pkiuser ca
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
drwxrwx--- pkiuser pkiuser tks
-rw-rw---- pkiuser pkiuser tomcat.conf
drwxrwx--- pkiuser pkiuser tps
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
drwxrwx--- pkiuser pkiuser ca
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser kra
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
drwxrwx--- pkiuser pkiuser tks
-rw-rw---- pkiuser pkiuser tomcat.conf
drwxrwx--- pkiuser pkiuser tps
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server conf dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser kra
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser tks
drwxrwx--- pkiuser pkiuser tps
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server logs dir after removal (rc=$_rc)" >&2
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/tps -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== tps-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== tps-basic-test PASSED ===="
