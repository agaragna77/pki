#!/bin/bash
# Generated TMT port of .github/workflows/kra-sskg-test.yml
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_admin_nickname=admin \
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
    -D pki_admin_nickname=admin \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file $SHARED/kra_transport.crt \
    kra_transport

TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec pki pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# by default KRA connector should contain transport cert data
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=pki.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# drop transport cert data from KRA connector
docker exec pki pki-server ca-config-unset ca.connector.KRA.transportCert

# check transport cert in NSS database
docker exec pki pki-server cert-show kra_transport

# set transport cert nickname in KRA connector
docker exec pki pki-server ca-config-set ca.connector.KRA.transportCertNickname kra_transport

docker exec pki pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should contain transport cert nickname
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=pki.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCertNickname=kra_transport
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec pki pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki nss-cert-import \
    --cert $SHARED/kra_transport.crt \
    kra_transport

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123

docker exec pki pki nss-cert-find

docker exec pki pki -n admin ca-user-show caadmin

docker exec pki pki -n admin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create request template for caServerKeygen_UserCert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get request template
docker exec pki curl \
    -s \
    -o - \
    --cacert $SHARED/ca_signing.crt \
    https://pki.example.com:8443/ca/v2/certrequests/profiles/caServerKeygen_UserCert \
    | tee caServerKeygen_UserCert.json

# configure request to create 2048-bit RSA key
cat caServerKeygen_UserCert.json \
    | jq '.Input[0].Attribute[1].Value|="RSA" | .Input[0].Attribute[2].Value|="2048"' \
    | tee template.json
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create request template for caServerKeygen_UserCert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Submit request with good password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create request with good password for user test1
#
# by default the password must be at least 20 characters,
# contain at least 2 upper case letters, and contain at
# least 1 special character.
cat template.json \
    | jq '.Input[0].Attribute[0].Value|="k342r09cmIJmklOLIJ,lwerkln234lik-[df"' \
    | jq '.Input[1].Attribute[0].Value|="test1"' \
    | tee request.json

# submit request
docker exec pki curl \
    -s \
    -o - \
    --cacert $SHARED/ca_signing.crt \
    --json @$SHARED/request.json \
    https://pki.example.com:8443/ca/v2/certrequests \
    | tee response.json

# request should be pending
jq -r '.entries[0].requestStatus' response.json > actual

cat > expected << EOF
pending
EOF

diff expected actual

# approve request
REQUEST_ID=$(jq -r '.entries[0].requestID' response.json)
docker exec pki pki \
    -n admin \
    ca-cert-request-approve \
    --force \
    $REQUEST_ID \
    | tee output

# export cert
CERT_ID=$(sed -n 's/^\s*Certificate ID:\s*\(\S*\)$/\1/p' output)
docker exec pki pki ca-cert-export \
    --output-file $SHARED/test1.crt \
    $CERT_ID
echo "Cert ID: $CERT_ID"
echo $CERT_ID > test1.cert_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Submit request with good password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Find generated key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find generated key by owner
docker exec pki pki \
    -n admin \
    kra-key-find \
    --owner UID=test1 \
    | tee output

KEY_ID=$(sed -n 's/^\s*Key ID:\s*\(\S*\)$/\1/p' output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > test1.key_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find generated key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve generated key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat test1.key_id)
echo "Key ID: $KEY_ID"

# export cert into Base64-encoded format
BASE64_CERT=$(openssl x509 -in test1.crt -outform DER | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

# create retrieval request with key ID, cert, and passphrase
cat > request.json <<EOF
{
  "ClassName" : "com.netscape.certsrv.key.KeyRecoveryRequest",
  "Attributes" : {
    "Attribute" : [ {
      "name" : "keyId",
      "value" : "$KEY_ID"
    }, {
      "name" : "certificate",
      "value" : "$BASE64_CERT"
    }, {
      "name" : "passphrase",
      "value" : "Secret.123"
    } ]
  }
}
EOF

# retrieve cert and key into PKCS #12 file
docker exec pki pki \
    -n admin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --transport kra_transport \
    --output-data test1.p12

docker exec pki pki pkcs12-cert-find \
    --pkcs12 test1.p12 \
    --password Secret.123

docker exec pki pki pkcs12-key-find \
    --pkcs12 test1.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve generated key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import retrieved key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import PKCS #12 file into NSS database with the passphrase
docker exec pki pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 test1.p12 \
    --password Secret.123

# remove retrieved cert from NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-del \
    UID=test1

# import original cert into NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-import \
    --cert $SHARED/test1.crt \
    test1

# the original cert should match the retrieved key (trust flags must be u,u,u)
docker exec pki pki \
    -d nssdb \
    nss-cert-show \
    test1 \
    | tee output

cat > expected << EOF
u,u,u
EOF

sed -n 's/^\s*Trust Flags:\s*\(\S\+\)$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import retrieved key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Submit request with short password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create request with short password for user test2
cat template.json \
    | jq '.Input[0].Attribute[0].Value|="k342r0"' \
    | jq '.Input[1].Attribute[0].Value|="test2"' \
    | tee request.json

# submit request
docker exec pki curl \
    -s \
    -o - \
    --cacert $SHARED/ca_signing.crt \
    --json @$SHARED/request.json \
    https://pki.example.com:8443/ca/v2/certrequests \
    | tee response.json

# request should be rejected
jq -r '.entries[0].requestStatus, .entries[0].errorMessage' response.json > actual

cat > expected <<EOF
rejected
The password must be at least 20 characters
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Submit request with short password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Submit request with numeric password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create request with numeric password for user test3
cat template.json \
    | jq '.Input[0].Attribute[0].Value|="1234567890246801357938"' \
    | jq '.Input[1].Attribute[0].Value|="test3"' \
    | tee request.json

# submit request
docker exec pki curl \
    -s \
    -o - \
    --cacert $SHARED/ca_signing.crt \
    --json @$SHARED/request.json \
    https://pki.example.com:8443/ca/v2/certrequests \
    | tee response.json

# request should be rejected
jq -r '.entries[0].requestStatus, .entries[0].errorMessage' response.json > actual

cat > expected <<EOF
rejected
The password requires at least 2 upper case letter(s)
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Submit request with numeric password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Disable PKCS #12 password constraint"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# disable p12ExportPasswordConstraintImpl
docker exec pki sed -i \
    's/^policyset.userCertSet.list=1,10,2,3,4,5,6,7,8,9,11/policyset.userCertSet.list=1,10,2,3,4,5,6,7,8,9/' \
    /etc/pki/pki-tomcat/ca/profiles/ca/caServerKeygen_UserCert.cfg

docker exec pki pki-server ca redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Disable PKCS #12 password constraint (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Submit request with minimal password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create request with minimal password for user test4
cat template.json \
    | jq '.Input[0].Attribute[0].Value|="1"' \
    | jq '.Input[1].Attribute[0].Value|="test4"' \
    | tee request.json

# submit request
docker exec pki curl \
    -s \
    -o - \
    --cacert $SHARED/ca_signing.crt \
    --json @$SHARED/request.json \
    https://pki.example.com:8443/ca/v2/certrequests \
    | tee response.json

# request should be pending
jq -r '.entries[0].requestStatus' response.json > actual

cat > expected << EOF
pending
EOF

diff expected actual

# approve request
REQUEST_ID=$(jq -r '.entries[0].requestID' response.json)
docker exec pki pki \
    -n admin \
    ca-cert-request-approve \
    --force \
    $REQUEST_ID \
    | tee output

# export cert
CERT_ID=$(sed -n 's/^\s*Certificate ID:\s*\(\S*\)$/\1/p' output)
docker exec pki pki ca-cert-export \
    --output-file $SHARED/test4.crt \
    $CERT_ID
echo "Cert ID: $CERT_ID"
echo $CERT_ID > test4.cert_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Submit request with minimal password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Find generated key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find generated key by owner
docker exec pki pki \
    -n admin \
    kra-key-find \
    --owner UID=test4 \
    | tee output

KEY_ID=$(sed -n 's/^\s*Key ID:\s*\(\S*\)$/\1/p' output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > test4.key_id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find generated key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve generated key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat test4.key_id)
echo "Key ID: $KEY_ID"

# export cert into Base64-encoded format
BASE64_CERT=$(openssl x509 -in test4.crt -outform DER | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

# create retrieval request with key ID, cert, and passphrase
cat > request.json <<EOF
{
  "ClassName" : "com.netscape.certsrv.key.KeyRecoveryRequest",
  "Attributes" : {
    "Attribute" : [ {
      "name" : "keyId",
      "value" : "$KEY_ID"
    }, {
      "name" : "certificate",
      "value" : "$BASE64_CERT"
    }, {
      "name" : "passphrase",
      "value" : "Secret.123"
    } ]
  }
}
EOF

# retrieve cert and key into PKCS #12 file
docker exec pki pki \
    -n admin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --transport kra_transport \
    --output-data test4.p12

docker exec pki pki pkcs12-cert-find \
    --pkcs12 test4.p12 \
    --password Secret.123

docker exec pki pki pkcs12-key-find \
    --pkcs12 test4.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve generated key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import generated key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import PKCS #12 file into NSS database with the passphrase
docker exec pki pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 test4.p12 \
    --password Secret.123

# remove retrieved cert from NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-del \
    UID=test4

# import original cert into NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-import \
    --cert $SHARED/test4.crt \
    test4

# the original cert should match the retrieved key (trust flags must be u,u,u)
docker exec pki pki \
    -d nssdb \
    nss-cert-show \
    test4 \
    | tee output

cat > expected << EOF
u,u,u
EOF

sed -n 's/^\s*Trust Flags:\s*\(\S\+\)$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import generated key (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-sskg-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-sskg-test PASSED ===="
