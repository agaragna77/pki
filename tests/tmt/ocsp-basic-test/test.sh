#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-basic-test.yml
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

step "Check pki ocsp CLI help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ocsp
docker exec pki pki ocsp --help

docker exec pki pki ocsp-cert-verify --help

docker exec pki pki ocsp-user-find --help
docker exec pki pki ocsp-user-show --help

docker exec pki pki ocsp-group-find --help
docker exec pki pki ocsp-group-show --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ocsp CLI help messages (rc=$_rc)" >&2
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

step "Check PKI system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-find
docker exec pki pki-server cert-show ca_signing
docker exec pki pki-server cert-show ca_ocsp_signing
docker exec pki pki-server cert-show sslserver
docker exec pki pki-server cert-show subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server subsystem-cert-find ca
docker exec pki pki-server subsystem-cert-show ca signing
docker exec pki pki-server subsystem-cert-show ca ocsp_signing
docker exec pki pki-server subsystem-cert-show ca sslserver
docker exec pki pki-server subsystem-cert-show ca subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain config in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# CA should run security domain service
cat > expected << EOF
securitydomain.checkIP=false
securitydomain.checkinterval=300000
securitydomain.flushinterval=86400000
securitydomain.host=pki.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=EXAMPLE
securitydomain.select=new
securitydomain.source=ldap
EOF

docker exec pki pki-server ca-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual

docker exec pki pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

# REST API should return security domain info
cat > expected << EOF
  Domain: EXAMPLE

  CA Subsystem:

    Host ID: CA pki.example.com 8443
    Hostname: pki.example.com
    Port: 8080
    Secure Port: 8443
    Domain Manager: TRUE

EOF
docker exec pki pki securitydomain-show | tee output
diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp.cfg \
    -s OCSP \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP (rc=$_rc)" >&2
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

step "Check PKI system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-find
docker exec pki pki-server cert-show ca_signing
docker exec pki pki-server cert-show ca_ocsp_signing
docker exec pki pki-server cert-show sslserver
docker exec pki pki-server cert-show subsystem
docker exec pki pki-server cert-show ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server subsystem-cert-find ocsp
docker exec pki pki-server subsystem-cert-show ocsp signing
docker exec pki pki-server subsystem-cert-show ocsp sslserver
docker exec pki pki-server subsystem-cert-show ocsp subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser ocsp
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser ca
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser ocsp
drwxrwx--- pkiuser pkiuser temp
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
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- pkiuser pkiuser ocsp
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
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
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- pkiuser pkiuser ocsp
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
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
-rw-rw---- pkiuser pkiuser ocsp.xml
-rw-rw---- pkiuser pkiuser pki.xml
lrwxrwxrwx pkiuser pkiuser rewrite.config -> /usr/share/pki/server/conf/Catalina/localhost/rewrite.config
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
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
drwxr-xr-x pkiuser pkiuser pki
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
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
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

step "Check OCSP base dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat/ocsp \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/alias
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/ocsp
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/ocsp
lrwxrwxrwx pkiuser pkiuser registry -> /etc/sysconfig/pki/tomcat/pki-tomcat
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/alias
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/ocsp
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/ocsp
lrwxrwxrwx pkiuser pkiuser registry -> /etc/sysconfig/pki/tomcat/pki-tomcat
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP base dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP conf dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat/conf/ocsp \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

cat > expected_new << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server status | tee output

# CA should be a domain manager, but OCSP should not
echo "True" > expected
echo "False" >> expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain config in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# OCSP should join security domain in CA
cat > expected << EOF
securitydomain.host=pki.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=EXAMPLE
securitydomain.select=existing
EOF

docker exec pki pki-server ocsp-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ocsp_signing \
    --cert-file ocsp_signing.crt
docker exec pki openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ocsp_signing.csr
docker exec pki openssl x509 -text -noout -in ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP signing cert (rc=$_rc)" >&2
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

step "Check OCSP admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP publishing in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find | grep ^ca.publish. | sort > output

cat > expected << EOF
ca.publish.enable=true
EOF
sed -n '/^ca.publish.enable=/p' output | tee actual
diff expected actual

cat > expected << EOF
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.enableClientAuth=true
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.host=pki.example.com
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.nickName=subsystem
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.path=/ocsp/agent/ocsp/addCRL
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.pluginName=OCSPPublisher
ca.publish.publisher.instance.OCSPPublisher-pki-example-com-8443.port=8443
EOF
sed -n '/^ca.publish.publisher.instance.OCSPPublisher-/p' output | tee actual
diff expected actual

cat > expected << EOF
ca.publish.rule.instance.ocsprule-pki-example-com-8443.enable=true
ca.publish.rule.instance.ocsprule-pki-example-com-8443.mapper=NoMap
ca.publish.rule.instance.ocsprule-pki-example-com-8443.pluginName=Rule
ca.publish.rule.instance.ocsprule-pki-example-com-8443.publisher=OCSPPublisher-pki-example-com-8443
ca.publish.rule.instance.ocsprule-pki-example-com-8443.type=crl
EOF
sed -n '/^ca.publish.rule.instance.ocsprule-/p' output | tee actual
diff expected actual

# set buffer size to 0 so that revocation will take effect immediately
docker exec pki pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec pki pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP publishing in CA (rc=$_rc)" >&2
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

step "Initialize PKI client"
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize PKI client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare initial cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CA agent and its cert
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-create.sh
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-create.sh

# get cert serial number
docker exec pki pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

echo "$CERT_ID" > cert.id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare initial cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# responder should fail since there's no CRLs
cat > expected << EOF
ERROR: OCSPResponseStatus: INTERNAL_ERROR
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -d /root/.dogtag/nssdb \
    -h pki.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

sed -n "/^SEVERE:/p" stderr > actual

# responder should fail since there's no CRLs
cat > expected << EOF
SEVERE: CLIException: OCSPResponseStatus: INTERNAL_ERROR
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ocsp/ee/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_ID \
    | tee output

# responder should fail since there's no CRLs
cat > expected << EOF
Responder Error: internalerror (2)
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare revoked cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# revoke CA agent cert
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-revoke.sh

# wait for CRL update
sleep 5

# get cert serial number
docker exec pki pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

echo "$CERT_ID" > cert.id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare revoked cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be revoked
cat > expected << EOF
  Status: Revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -d /root/.dogtag/nssdb \
    -h pki.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    | tee output

sed -n "/^CertStatus=/p" output > actual

# cert status should be revoked
cat > expected << EOF
CertStatus=Revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ocsp/ee/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_ID \
    | tee output

sed -n "/^$CERT_ID:/p" output > actual

# cert status should be revoked
cat > expected << EOF
$CERT_ID: revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare good cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# unrevoke CA agent cert
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-unrevoke.sh

# wait for CRL update
sleep 5

# get cert serial number
docker exec pki pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

echo "$CERT_ID" > cert.id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare good cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be good
cat > expected << EOF
  Status: Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -d /root/.dogtag/nssdb \
    -h pki.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    | tee output

sed -n "/^CertStatus=/p" output > actual

# cert status should be good
cat > expected << EOF
CertStatus=Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ocsp/ee/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_ID \
    | tee output

sed -n "/^$CERT_ID:/p" output > actual

# cert status should be good
cat > expected << EOF
$CERT_ID: good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare non-existent cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# pick a non-existent serial number
CERT_ID=0x1
echo "$CERT_ID" > cert.id

docker exec pki pki ca-cert-show $CERT_ID || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare non-existent cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder non-existent cert using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be good
cat > expected << EOF
  Status: Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder non-existent cert using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder non-existent cert using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -d /root/.dogtag/nssdb \
    -h pki.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    | tee output

sed -n "/^CertStatus=/p" output > actual

# cert status should be good
cat > expected << EOF
CertStatus=Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder non-existent cert using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder non-existent cert using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ocsp/ee/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_ID \
    | tee output

sed -n "/^$CERT_ID:/p" output > actual

# cert status should be good
cat > expected << EOF
$CERT_ID: good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder non-existent cert using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP for non-existent cert using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --path /ca/ocsp \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be unknown
cat > expected << EOF
  Status: Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP for non-existent cert using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP for non-existent cert using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -d /root/.dogtag/nssdb \
    -h pki.example.com \
    -p 8080 \
    -t /ca/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    | tee output

sed -n "/^CertStatus=/p" output > actual

# cert status should be unknown
cat > expected << EOF
CertStatus=Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP for non-existent cert using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP for non-existent cert using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ca/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_ID \
    | tee output

sed -n "/^$CERT_ID:/p" output > actual

# cert status should be unknown
cat > expected << EOF
$CERT_ID: unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP for non-existent cert using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create request with wrong CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get cert serial number
docker exec pki pki nss-cert-show caagent | tee output

CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)
echo "$CERT_ID" > cert.id

# create self-signed CA signing cert
docker exec pki openssl req \
    -newkey rsa:2048 -nodes \
    -keyout wrong_ca.key \
    -x509 -days 365 -out wrong_ca.crt \
    -subj "/O=EXAMPLE/OU=pki-tomcat/CN=CA Signing Certificate External"

# create OCSP request
docker exec pki openssl ocsp \
    -issuer wrong_ca.crt \
    -serial $CERT_ID \
    -reqout wrong_ca.request
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create request with wrong CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check request with wrong CA using pki ocsp-cert-verify"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki pki \
    -U http://pki.example.com:8080 \
    ocsp-cert-verify \
    --request wrong_ca.request \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be unknown
cat > expected << EOF
  Status: Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request with wrong CA using pki ocsp-cert-verify (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check request with wrong CA using OCSPClient"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki OCSPClient \
    -h pki.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    --input wrong_ca.request \
    | tee output

sed -n "/^CertStatus=/p" output > actual

# cert status should be unknown
cat > expected << EOF
CertStatus=Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request with wrong CA using OCSPClient (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check request with wrong CA using OpenSSL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ocsp/ee/ocsp \
    -CAfile ca_signing.crt \
    -issuer wrong_ca.crt \
    -serial $CERT_ID \
    | tee output

sed -n "/^$CERT_ID:/p" output > actual

# cert status should be unknown
cat > expected << EOF
$CERT_ID: unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request with wrong CA using OpenSSL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy \
    -s OCSP \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP (rc=$_rc)" >&2
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
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- pkiuser pkiuser ocsp
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
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
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
drwxrwx--- pkiuser pkiuser ocsp
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
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
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
drwxr-xr-x pkiuser pkiuser pki
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
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser ca
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pkiuser ocsp
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

step "Check for PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -l
docker exec pki find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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

step "Check PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log (rc=$_rc)" >&2
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

step "Check OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ocsp-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-basic-test PASSED ===="
