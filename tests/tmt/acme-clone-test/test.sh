#!/bin/bash
# Generated TMT port of .github/workflows/acme-clone-test.yml
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
    docker rm -f ca cads client primaryacme primaryacmeds secondaryacme secondaryacmeds 2>/dev/null || true
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

docker exec ca dnf install -y xmlstarlet

# disable access log buffer
docker exec ca xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary ACME DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=primaryacmeds.example.com \
    --password=Secret.123 \
    --network=example \
    --network-alias=primaryacmeds.example.com \
    primaryacmeds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary ACME DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primaryacme.example.com \
    --network=example \
    --network-alias=primaryacme.example.com \
    --network-alias=acme.example.com \
    primaryacme
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme pkispawn \
    -f /usr/share/pki/server/examples/installation/acme.cfg \
    -s ACME \
    -D acme_database_url=ldap://primaryacmeds.example.com:3389 \
    -D acme_issuer_url=https://ca.example.com:8443 \
    -D acme_realm_url=ldap://primaryacmeds.example.com:3389 \
    -v

docker exec primaryacme dnf install -y xmlstarlet

# disable access log buffer
docker exec primaryacme xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary ACME database config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme cat /etc/pki/pki-tomcat/acme/database.conf | tee output

cat > expected << EOF
authType=BasicAuth
baseDN=dc=acme,dc=pki,dc=example,dc=com
bindDN=cn=Directory Manager
bindPassword=Secret.123
class=org.dogtagpki.acme.database.DSDatabase
url=ldap://primaryacmeds.example.com:3389
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME database config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary ACME issuer config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme cat /etc/pki/pki-tomcat/acme/issuer.conf | tee output

cat > expected << EOF
class=org.dogtagpki.acme.issuer.PKIIssuer
password=Secret.123
profile=acmeServerCert
url=https://ca.example.com:8443
username=caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME issuer config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary ACME realm config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme cat /etc/pki/pki-tomcat/acme/realm.conf | tee output

cat > expected << EOF
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=Secret.123
class=org.dogtagpki.acme.realm.DSRealm
groupsDN=ou=groups,dc=acme,dc=pki,dc=example,dc=com
url=ldap://primaryacmeds.example.com:3389
usersDN=ou=people,dc=acme,dc=pki,dc=example,dc=com
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME realm config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary ACME system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize primary ACME database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme pki-server acme-database-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize primary ACME database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize primary ACME realm"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme pki-server acme-realm-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize primary ACME realm (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary ACME DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacmeds ldapsearch \
    -H ldap://primaryacmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b dc=example,dc=com \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary ACME DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=secondaryacmeds.example.com \
    --password=Secret.123 \
    --network=example \
    --network-alias=secondaryacmeds.example.com \
    secondaryacmeds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary ACME DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondaryacme.example.com \
    --network=example \
    --network-alias=secondaryacme.example.com \
    secondaryacme
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install secondary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme pkispawn \
    -f /usr/share/pki/server/examples/installation/acme.cfg \
    -s ACME \
    -D acme_database_url=ldap://secondaryacmeds.example.com:3389 \
    -D acme_issuer_url=https://ca.example.com:8443 \
    -D acme_realm_url=ldap://secondaryacmeds.example.com:3389 \
    -v

docker exec secondaryacme dnf install -y xmlstarlet

# disable access log buffer
docker exec secondaryacme xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install secondary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary ACME database config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme cat /etc/pki/pki-tomcat/acme/database.conf | tee output

cat > expected << EOF
authType=BasicAuth
baseDN=dc=acme,dc=pki,dc=example,dc=com
bindDN=cn=Directory Manager
bindPassword=Secret.123
class=org.dogtagpki.acme.database.DSDatabase
url=ldap://secondaryacmeds.example.com:3389
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME database config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary ACME issuer config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme cat /etc/pki/pki-tomcat/acme/issuer.conf | tee output

cat > expected << EOF
class=org.dogtagpki.acme.issuer.PKIIssuer
password=Secret.123
profile=acmeServerCert
url=https://ca.example.com:8443
username=caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME issuer config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary ACME realm config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme cat /etc/pki/pki-tomcat/acme/realm.conf | tee output

cat > expected << EOF
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=Secret.123
class=org.dogtagpki.acme.realm.DSRealm
groupsDN=ou=groups,dc=acme,dc=pki,dc=example,dc=com
url=ldap://secondaryacmeds.example.com:3389
usersDN=ou=people,dc=acme,dc=pki,dc=example,dc=com
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME realm config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary ACME system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up ACME database and realm replication"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# enable replication in primary ACME DS
docker exec primaryacmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryacmeds.example.com:3389 \
    replication enable \
    --suffix=dc=example,dc=com \
    --role=supplier \
    --replica-id=1 \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123

# enable replication in secondary ACME DS
docker exec secondaryacmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryacmeds.example.com:3389 \
    replication enable \
    --suffix=dc=example,dc=com \
    --role=supplier \
    --replica-id=2 \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123

# create replication agreement in primary ACME DS
docker exec primaryacmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryacmeds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=example,dc=com \
    --host=secondaryacmeds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    primaryacmeds-to-secondaryacmeds

# create replication agreement in secondary ACME DS
docker exec secondaryacmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryacmeds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=example,dc=com \
    --host=primaryacmeds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    secondaryacmeds-to-primaryacmeds

# start replication initialization
docker exec primaryacmeds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryacmeds.example.com:3389 \
    repl-agmt init \
    --suffix=dc=example,dc=com \
    primaryacmeds-to-secondaryacmeds

# wait for initialization to complete
while true; do
    sleep 1

    docker exec primaryacmeds dsconf \
        -D "cn=Directory Manager" \
        -w Secret.123 \
        ldap://primaryacmeds.example.com:3389 \
        repl-agmt init-status \
        --suffix=dc=example,dc=com \
        primaryacmeds-to-secondaryacmeds \
        | tee output

    MSG=$(cat output)
    if [ "$MSG" = "Agreement successfully initialized." ]; then
        break
    fi
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME database and realm replication (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary ACME DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacmeds ldapsearch \
    -H ldap://secondaryacmeds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b dc=example,dc=com \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME DS (rc=$_rc)" >&2
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

step "Register account in primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://acme.example.com:8080/acme/directory \
    --email testuser@example.com \
    --agree-tos \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register account in primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check accounts in secondary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacmeds ldapsearch \
    -H ldap://secondaryacmeds.example.com:3389 \
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
    echo "FAIL: Check accounts in secondary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Move acme.example.com to secondary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker network disconnect example primaryacme
docker network connect example primaryacme \
    --alias primaryacme.example.com

docker network disconnect example secondaryacme
docker network connect example secondaryacme \
    --alias secondaryacme.example.com \
    --alias acme.example.com
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Move acme.example.com to secondary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll client cert against secondary ACME"
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
    echo "FAIL: Enroll client cert against secondary ACME (rc=$_rc)" >&2
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

step "Check orders in primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacmeds ldapsearch \
    -H ldap://primaryacmeds.example.com:3389 \
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
    echo "FAIL: Check orders in primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorizations in primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacmeds ldapsearch \
    -H ldap://primaryacmeds.example.com:3389 \
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
    echo "FAIL: Check authorizations in primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check challenges in primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacmeds ldapsearch \
    -H ldap://primaryacmeds.example.com:3389 \
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
    echo "FAIL: Check challenges in primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacmeds ldapsearch \
    -H ldap://primaryacmeds.example.com:3389 \
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
    echo "FAIL: Check certs in primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove secondary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondaryacme pkidestroy -s ACME -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryacme pkidestroy -s ACME -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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

step "Check CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA access log (rc=$_rc)" >&2
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

step "Check primary ACME DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryacmeds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary ACME DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs primaryacmeds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary ACME server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryacme journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary ACME access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryacme find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary ACME debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryacme find /var/lib/pki/pki-tomcat/logs/acme -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary ACME debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary ACME DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryacmeds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary ACME DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs secondaryacmeds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary ACME server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryacme journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary ACME access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryacme find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary ACME debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryacme find /var/lib/pki/pki-tomcat/logs/acme -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary ACME debug log (rc=$_rc)" >&2
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
    echo "==== acme-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-clone-test PASSED ===="
