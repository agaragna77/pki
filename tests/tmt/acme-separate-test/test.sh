#!/bin/bash
# Generated TMT port of .github/workflows/acme-separate-test.yml
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

export DS_IMAGE="pki-runner"
export SHARED="/tmp/workdir/pki"

PKI_IMAGE="${PKI_IMAGE:-pki-runner}"

# Ensure docker and pki-runner are available
if ! command -v docker >/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

cleanup() {
    docker rm -f acme acmeds ca cads client 2>/dev/null || true
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

step "Set up CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=cads.example.com \
    --password=Secret.123 \
    --network=example \
    --network-alias=cads.example.com \
    cads

docker exec cads dsconf \
    localhost \
    backend \
    config \
    get \
    | tee output

# CA DS backend should be LMDB
echo "nsslapd-backend-implement: mdb" > expected
cat output | sed -n "/^nsslapd-backend-implement:/p" > actual

diff expected actual
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

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec ca sed -n 's/^VERSION_ID=//p' /etc/os-release)
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
    --trust CT,C,C \
    ca_signing

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

docker exec ca pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-find | tee output

# there should be 6 certs
echo "6" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up ACME DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=acmeds.example.com \
    --password=Secret.123 \
    --network=example \
    --network-alias=acmeds.example.com \
    acmeds

# create DS backend
docker exec acmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://acmeds.example.com:3389 \
    backend create \
    --suffix=dc=acme,dc=pki,dc=example,dc=com \
    --be-name=acme

docker exec acmeds dsconf \
    localhost \
    backend \
    config \
    get \
    | tee output

# ACME DS backend should be LMDB
echo "nsslapd-backend-implement: mdb" > expected
cat output | sed -n "/^nsslapd-backend-implement:/p" > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=acme.example.com \
    --network=example \
    --network-alias=acme.example.com \
    acme
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pkispawn \
    -f /usr/share/pki/server/examples/installation/acme.cfg \
    -s ACME \
    -D acme_database_url=ldap://acmeds.example.com:3389 \
    -D acme_issuer_url=https://ca.example.com:8443 \
    -D acme_realm_url=ldap://acmeds.example.com:3389 \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install ACME (rc=$_rc)" >&2
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

step "Check ACME server base dir after installation"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser acme
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

 cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser acme
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server base dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME server conf dir after installation"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server conf dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME base dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme ls -l /var/lib/pki/pki-tomcat/acme \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/acme
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/acme
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser conf -> /var/lib/pki/pki-tomcat/conf/acme
lrwxrwxrwx pkiuser pkiuser logs -> /var/lib/pki/pki-tomcat/logs/acme
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME base dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /etc/pki/pki-tomcat/acme \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
-rw-rw---- pkiuser pkiuser database.conf
-rw-rw---- pkiuser pkiuser issuer.conf
-rw-rw---- pkiuser pkiuser realm.conf
EOF

cat > expected_new << EOF
-rw-rw---- pkiuser pkiuser database.conf
-rw-rw---- pkiuser pkiuser issuer.conf
-rw-rw---- pkiuser pkiuser realm.conf
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME database config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme cat /etc/pki/pki-tomcat/acme/database.conf
docker exec acme pki-server acme-database-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME database config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME issuer config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme cat /etc/pki/pki-tomcat/acme/issuer.conf
docker exec acme pki-server acme-issuer-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME issuer config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME realm config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme cat /etc/pki/pki-tomcat/acme/realm.conf
docker exec acme pki-server acme-realm-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME realm config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME logs dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme ls -l /var/log/pki/pki-tomcat/acme
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME system certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Initialize ACME database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# rebuild ACME indexes later
docker exec acme pki-server acme-database-init \
    --ds-backend acme \
    --skip-reindex \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize ACME realm"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pki-server acme-realm-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME realm (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME accounts"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=accounts,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no accounts
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME accounts (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME orders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=orders,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no orders
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME orders (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME authorizations"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=authorizations,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no authorizations
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME authorizations (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME challenges"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=challenges,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no challenges
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME challenges (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=certificates,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no certs
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after ACME installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-find | tee output

# there should be 7 certs
echo "7" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after ACME installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in CA container"
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
    docker exec ca pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in ACME container"
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
    docker exec acme pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify ACME in ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec acme pki acme-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify ACME in ACME container (rc=$_rc)" >&2
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

step "Install certbot in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y certbot
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install certbot in client container (rc=$_rc)" >&2
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
    --email testuser@example.com \
    --agree-tos \
    --non-interactive \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# registration should fail since ACME indexes has not been rebuilt
echo "acme.errors.ClientError: <Response [500]>" > expected
cat stderr | sed -n '/^acme.errors.ClientError:/p' > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Rebuild ACME indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# LMDB indexes must be rebuilt
docker exec acme pki-server acme-database-index-rebuild \
    --ds-backend acme \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Rebuild ACME indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register ACME account again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://acme.example.com:8080/acme/directory \
    --email testuser@example.com \
    --agree-tos \
    --non-interactive

# registration should work
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register ACME account again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME accounts after registration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=accounts,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one account
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual

# status should be valid
echo "valid" > expected
sed -n 's/^acmeStatus: *\(.*\)$/\1/p' output > actual
diff expected actual

# email should be testuser@example.com
echo "mailto:testuser@example.com" > expected
sed -n 's/^acmeAccountContact: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after registration (rc=$_rc)" >&2
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
docker exec client pki client-cert-import \
    --cert /etc/letsencrypt/live/client.example.com/fullchain.pem \
    client1

# store serial number
docker exec client pki nss-cert-show client1 | tee output
sed -n 's/^ *Serial Number: *\(.*\)/\1/p' output > serial1.txt

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME orders after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=orders,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one order
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME orders after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME authorizations after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=authorizations,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one authorization
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME authorizations after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME challenges after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=challenges,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one challenge
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME challenges after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME certs after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=certificates,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no certs (they are stored in CA)
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME certs after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-find | tee output

# there should be 8 certs
echo "8" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check client cert
SERIAL=$(cat serial1.txt)
docker exec ca pki ca-cert-show $SERIAL | tee output

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after enrollment (rc=$_rc)" >&2
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

step "Check renewed client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki client-cert-import \
    --cert /etc/letsencrypt/live/client.example.com/fullchain.pem \
    client2

# store serial number
docker exec client pki nss-cert-show client2 | tee output
sed -n 's/^ *Serial Number: *\(.*\)/\1/p' output > serial2.txt

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check renewed client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME orders after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=orders,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be two orders
echo "2" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME orders after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME authorizations after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=authorizations,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be two authorizations
echo "2" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME authorizations after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME challenges after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=challenges,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be two challenges
echo "2" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME challenges after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=certificates,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be no certs (they are stored in CA)
echo "0" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-find | tee output

# there should be 9 certs
echo "9" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check renewed client cert
SERIAL=$(cat serial2.txt)
docker exec ca pki ca-cert-show $SERIAL | tee output

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot revoke \
    --server http://acme.example.com:8080/acme/directory \
    --cert-name client.example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki ca-cert-find | tee output

# there should be 9 certs
echo "9" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check original client cert
SERIAL=$(cat serial1.txt)
docker exec ca pki ca-cert-show $SERIAL | tee output

# status should be valid
echo "VALID" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual

# check renewed-then-revoked client cert
SERIAL=$(cat serial2.txt)
docker exec ca pki ca-cert-show $SERIAL | tee output

# status should be revoked
echo "REVOKED" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after revocation (rc=$_rc)" >&2
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
    --email newuser@example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME accounts after update"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=accounts,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one account
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual

# email should be newuser@example.com
echo "mailto:newuser@example.com" > expected
sed -n 's/^acmeAccountContact: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after update (rc=$_rc)" >&2
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

step "Check ACME accounts after unregistration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acmeds ldapsearch \
    -H ldap://acmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b ou=accounts,dc=acme,dc=pki,dc=example,dc=com \
    -s one \
    -o ldif_wrap=no \
    -LLL | tee output

# there should be one account
echo "1" > expected
{ grep "^dn:" output || true; } | wc -l > actual
diff expected actual

# status should be deactivated
echo "deactivated" > expected
sed -n 's/^acmeStatus: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after unregistration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pkidestroy \
    -s ACME \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME (rc=$_rc)" >&2
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
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME server base dir after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/lib/pki/pki-tomcat \
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
    echo "FAIL: Check ACME server base dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME server conf dir after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server conf dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec acme ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser acme
drwxrwx--- pkiuser pkiuser backup
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server logs dir after removal (rc=$_rc)" >&2
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

step "Check CA server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA server systemd journal (rc=$_rc)" >&2
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

step "Check ACME DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acmeds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs acmeds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec acme find /var/lib/pki/pki-tomcat/logs/acme -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certbot log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec client cat /var/log/letsencrypt/letsencrypt.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certbot log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== acme-separate-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-separate-test PASSED ===="
