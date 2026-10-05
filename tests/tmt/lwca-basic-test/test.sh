#!/bin/bash
# Generated TMT port of .github/workflows/lwca-basic-test.yml
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
    docker rm -f pki 2>/dev/null || true
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

step "Check pki ca-authority CLI help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-authority-find --help
docker exec pki pki ca-authority-show --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-authority CLI help messages (rc=$_rc)" >&2
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
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin user"
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
docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check host CA's LDAP entry"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "ou=authorities,ou=ca,dc=ca,dc=pki,dc=example,dc=com" \
    -s one \
    -o ldif_wrap=no \
    -LLL \
    "(objectClass=*)" \
    "*" \
    entryUSN \
    nsUniqueId \
    | tee output

HOSTCA_ID=$(sed -n 's/^cn:\s*\(.*\)$/\1/p' output | tee hostca-id)
echo "HOSTCA_ID: $HOSTCA_ID"

# check authorityKeyNickname
echo "ca_signing" > expected
sed -n 's/^authorityKeyNickname:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check host CA's LDAP entry (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs and keys in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-find | tee output

# there should be 5 certs
echo "5" > expected
sed -n 's/^\s*Nickname:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find | tee output

# there should be 5 keys
echo "5" > expected
sed -n 's/^\s*Key ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs and keys in NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check host CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-authority-find | tee output

# there should be 1 authority initially
echo "1" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual

# it should be a host CA
echo "true" > expected
sed -n 's/^\s*Host authority:\s*\(.*\)$/\1/p' output > actual
diff expected actual

# check host CA ID
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > actual
diff hostca-id actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check host CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create lightweight CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

# create 20 LWCAs under the host CA
for i in {1..20}
do
    docker exec pki pki -n caadmin ca-authority-create \
        --parent $HOSTCA_ID \
        CN="Lightweight CA $i" | tee output

    # store LWCA ID
    sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output >> lwca-id
done

docker exec pki pki -n caadmin ca-authority-find | tee output

# there should be 21 authorities now
echo -e "$HOSTCA_ID\n$(cat lwca-id)" | sort > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create lightweight CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authority LDAP entries"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "ou=authorities,ou=ca,dc=ca,dc=pki,dc=example,dc=com" \
    -s one \
    -o ldif_wrap=no \
    -LLL \
    "(objectClass=*)" \
    "*" \
    entryUSN \
    nsUniqueId \
    | tee output

# check authorityKeyNicknames
echo "ca_signing" > expected
for LWCA_ID in $(cat lwca-id)
do
    echo -e "ca_signing $LWCA_ID" >> expected
done
sort -o expected expected

sed -n 's/^authorityKeyNickname:\s*\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authority LDAP entries (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs and keys in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-find | tee output

# there should be 25 certs now
echo "25" > expected
sed -n 's/^\s*Nickname:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find | tee output

# there should be 25 keys now
echo "25" > expected
sed -n 's/^\s*Key ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs and keys in NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check enrollment against lightweight CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# use the first LWCA
LWCA_ID=$(head -1 lwca-id)

# get LWCA's DN
docker exec pki pki -n caadmin ca-authority-show $LWCA_ID | tee output
sed -n -e 's/^\s*Authority DN:\s*\(.*\)$/\1/p' output > expected

# submit enrollment request against LWCA
docker exec pki pki client-cert-request \
    --issuer-id $LWCA_ID \
    UID=testuser | tee output

# get request ID
REQUEST_ID=$(sed -n -e 's/^\s*Request ID:\s*\(.*\)$/\1/p' output)

# approve request
docker exec pki pki \
    -n caadmin \
    ca-cert-request-approve \
    $REQUEST_ID \
    --force | tee output

# get cert ID
CERT_ID=$(sed -n -e 's/^\s*Certificate ID:\s*\(.*\)$/\1/p' output)

docker exec pki pki ca-cert-show $CERT_ID | tee output

# verify that it's signed by LWCA
sed -n -e 's/^\s*Issuer DN:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check enrollment against lightweight CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove lightweight CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

for LWCA_ID in $(cat lwca-id)
do
    docker exec pki pki -n caadmin ca-authority-disable $LWCA_ID

    docker exec pki pki -n caadmin ca-authority-del \
        --force \
        $LWCA_ID
done

docker exec pki pki -n caadmin ca-authority-find | tee output

# there should be 1 authority now
echo "$HOSTCA_ID" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove lightweight CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authority LDAP entries"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "ou=authorities,ou=ca,dc=ca,dc=pki,dc=example,dc=com" \
    -s one \
    -o ldif_wrap=no \
    -LLL \
    "(objectClass=*)" \
    "*" \
    entryUSN \
    nsUniqueId \
    | tee output

# there should be 1 entry now
sed -n 's/^\s*cn:\s*\(.*\)$/\1/p' output > actual
diff hostca-id actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authority LDAP entries (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs and keys in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-find | tee output

# there should be 5 certs now
echo "5" > expected
sed -n 's/^\s*Nickname:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual

docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find | tee output

# there should be 5 keys now
echo "5" > expected
sed -n 's/^\s*Key ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs and keys in NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug logs (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== lwca-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== lwca-basic-test PASSED ===="
