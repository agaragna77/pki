#!/bin/bash
# Generated TMT port of .github/workflows/est-ds-realm-separate-test.yml
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
    docker rm -f ca cads est 2>/dev/null || true
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
    --password=Secret.123 \
    --network=example \
    --network-alias=cads.example.com \
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize PKI client"
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
    --password Secret.123

docker exec ca pki info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize PKI client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up EST DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=estds.example.com \
    --password=Secret.123 \
    --network=example \
    --network-alias=estds.example.com \
    estds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up EST DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up EST container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
--hostname=est.example.com \
--network=example \
--network-alias=est.example.com \
est
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up EST container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec est sed -n 's/^VERSION_ID=//p' /etc/os-release)
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
TOMCAT_FLAVOR=$(docker exec est test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
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

step "Set up EST user DB"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i est ldapadd -x -H ldap://estds.example.com:3389 \
    -D "cn=Directory Manager"  -w Secret.123 \
    -f /usr/share/pki/est/conf/realm/ds/create.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up EST user DB (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install EST"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec est pkispawn \
    -f /usr/share/pki/server/examples/installation/est.cfg \
    -s EST \
    -D est_realm_url=ldap://estds.example.com:3389 \
    -D pki_ca_uri=https://ca.example.com:8443 \
    -D pki_security_domain_hostname=ca.example.com \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_cert_chain_nickname=caSigning \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install EST (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server base dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser est
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser temp
drwxrwx--- pkiuser pkiuser webapps
drwxrwx--- pkiuser pkiuser work
EOF

cat > expected_new << EOF
lrwxrwxrwx pkiuser pkiuser alias -> /var/lib/pki/pki-tomcat/conf/alias
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxrwx--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
drwxrwx--- pkiuser pkiuser est
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
    echo "FAIL: Check EST server base dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server conf dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser est
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser est
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
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
    echo "FAIL: Check EST server conf dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST conf dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /etc/pki/pki-tomcat/est \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser authorizer.conf
-rw-rw---- pkiuser pkiuser backend.conf
-rw-rw---- pkiuser pkiuser realm.conf
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

cat > expected_new << EOF
-rw-rw---- pkiuser pkiuser CS.cfg
-rw-rw---- pkiuser pkiuser authorizer.conf
-rw-rw---- pkiuser pkiuser backend.conf
-rw-rw---- pkiuser pkiuser realm.conf
-rw-rw---- pkiuser pkiuser registry.cfg
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Test CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec est curl -o cacert.p7 -k https://est.example.com:8443/.well-known/est/cacerts

docker exec est openssl base64 -d --in cacert.p7 --out cacert.p7.der
docker exec est openssl pkcs7 --in cacert.p7.der -inform DER -print_certs -quiet -out cacert.pem
docker exec est openssl x509 -in cacert.pem -text -noout | tee actual
docker exec est openssl x509 -in $SHARED/ca_signing.crt -text -noout | tee expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Test CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add EST user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i est ldapadd -x -H ldap://estds.example.com:3389 \
    -D "cn=Directory Manager"  -w Secret.123 <<EOF
dn: uid=est-test-user,ou=people,dc=est,dc=pki,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: est-test-user
sn: test.example.com
cn: test.example.com
userPassword: Secret.123
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add EST user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add EST user to EST Users group"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i est ldapmodify -x -H ldap://estds.example.com:3389 \
    -D "cn=Directory Manager"  -w Secret.123 <<EOF
dn: cn=EST Users,ou=groups,dc=est,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=est-test-user,ou=People,dc=est,dc=pki,dc=example,dc=com
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add EST user to EST Users group (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install est client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec est dnf copr enable -y @pki/libest 
docker exec est dnf install -y libest
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install est client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll certificate"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -e EST_OPENSSL_CACERT=cacert.pem est estclient -e -s est.example.com -p 8443 \
    --common-name test.example.com -o . -u est-test-user -h Secret.123

docker exec est openssl base64 -d --in cert-0-0.pkcs7 --out cert-0-0.pkcs7.der
docker exec est openssl pkcs7 -in cert-0-0.pkcs7.der -inform DER -print_certs -quiet -out cert.pem
docker exec est openssl x509 -in cert.pem -subject -noout | tee actual
echo "subject=CN=test.example.com" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll certificate (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove EST"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec est pkidestroy -i pki-tomcat -s EST -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove EST (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -i pki-tomcat -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server base dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/lib/pki/pki-tomcat \
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
    echo "FAIL: Check EST server base dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server conf dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser est
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser password.conf
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser serverCertNick.conf
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser Catalina
drwxrwx--- pkiuser pkiuser alias
-rw-r--r-- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
drwxrwx--- pkiuser pkiuser est
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
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
    echo "FAIL: Check EST server conf dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
drwxr-xr-x pkiuser pkiuser pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec est ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser pkiuser backup
drwxrwx--- pkiuser pkiuser est
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST server logs dir after removal (rc=$_rc)" >&2
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

step "Check CA PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA PKI server systemd journal (rc=$_rc)" >&2
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

step "Check for EST core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec est ls -l
docker exec est find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for EST core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec est journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check EST debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec est find /var/lib/pki/pki-tomcat/logs/est -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== est-ds-realm-separate-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== est-ds-realm-separate-test PASSED ===="
