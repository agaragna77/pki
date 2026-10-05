#!/bin/bash
# Generated TMT port of .github/workflows/kra-migration-test.yml
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
    docker rm -f ds1 ds2 pki1 pki2 2>/dev/null || true
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

step "Set up first DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=ds1.example.com \
    --network=example \
    --network-alias=ds1.example.com \
    --password=Secret.123 \
    --base-dn="dc=pki1,dc=example,dc=com" \
    ds1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up first DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up first PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki1.example.com \
    --network=example \
    --network-alias=pki1.example.com \
    pki1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up first PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install first CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds1.example.com:3389 \
    -D pki_ds_base_dn=dc=ca,dc=pki1,dc=example,dc=com \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install first CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check first CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-export \
    --output-file cert_chain.pem \
    --with-chain \
    ca_signing

docker exec pki1 pki nss-cert-import \
    --cert cert_chain.pem \
    --trust CT,C,C

docker exec pki1 pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki1 pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check first CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install first KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds1.example.com:3389 \
    -D pki_ds_base_dn=dc=kra,dc=pki1,dc=example,dc=com \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install first KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check first KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check first KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pki-server cert-export \
    --cert-file kra_transport.crt \
    kra_transport

# import transport cert
docker exec pki1 pki nss-cert-import \
    --cert kra_transport.crt \
    kra_transport

# generate key and cert request
# https://github.com/dogtagpki/pki/wiki/Generating-Certificate-Request-with-PKI-NSS
docker exec pki1 pki \
    nss-cert-request \
    --type crmf \
    --subject UID=testuser \
    --transport kra_transport \
    --csr testuser.csr

docker exec pki1 cat testuser.csr

# issue cert
# https://github.com/dogtagpki/pki/wiki/Issuing-Certificates
docker exec pki1 pki \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caUserCert \
    --subject UID=testuser \
    --csr-file testuser.csr \
    --output-file $SHARED/testuser.crt

# import cert into NSS database
docker exec pki1 pki nss-cert-import --cert $SHARED/testuser.crt testuser

# the cert should match the key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec pki1 pki nss-cert-show testuser | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)\s*$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived key in first KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find archived key by owner
docker exec pki1 pki \
    -u kraadmin \
    -w Secret.123 \
    kra-key-find \
    --owner UID=testuser | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > key.id

DEC_KEY_ID=$(python -c "print(int('$KEY_ID', 16))")
echo "Dec Key ID: $DEC_KEY_ID"

# get key record
docker exec ds1 ldapsearch \
    -H ldap://ds1.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "cn=$DEC_KEY_ID,ou=keyRepository,ou=kra,dc=kra,dc=pki1,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL | tee kra1.ldif

# encryption mode should be "false" by default
echo "false" > expected
sed -n 's/^metaInfo: payloadEncrypted:\(.*\)$/\1/p' kra1.ldif > actual
diff expected actual

# key wrap algorithm should be "AES KeyWrap/Padding" by default
echo "AES KeyWrap/Padding" > expected
sed -n 's/^metaInfo: payloadWrapAlgorithm:\(.*\)$/\1/p' kra1.ldif > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived key in first KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key retrieval from first KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

BASE64_CERT=$(docker exec pki1 pki nss-cert-export --format DER testuser | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

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

# retrieve archived cert and key into PKCS #12 file
# https://github.com/dogtagpki/pki/wiki/Retrieving-Archived-Key
docker exec pki1 pki \
    -n caadmin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --output-data archived.p12

# import PKCS #12 file into NSS database
docker exec pki1 pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 archived.p12 \
    --password Secret.123

# remove archived cert from NSS database
docker exec pki1 pki -d nssdb nss-cert-del UID=testuser

# import original cert into NSS database
docker exec pki1 pki -d nssdb nss-cert-import --cert $SHARED/testuser.crt testuser

# the original cert should match the archived key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec pki1 pki -d nssdb nss-cert-show testuser | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key retrieval from first KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up second DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=ds2.example.com \
    --network=example \
    --network-alias=ds2.example.com \
    --password=Secret.123 \
    --base-dn="dc=pki2,dc=example,dc=com" \
    ds2
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up second DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up second PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki2.example.com \
    --network=example \
    --network-alias=pki2.example.com \
    pki2
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up second PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install second CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds2.example.com:3389 \
    -D pki_ds_base_dn=dc=ca,dc=pki2,dc=example,dc=com \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install second CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check second CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-export \
    --output-file cert_chain.pem \
    --with-chain \
    ca_signing

docker exec pki2 pki nss-cert-import \
    --cert cert_chain.pem \
    --trust CT,C,C

docker exec pki2 pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki2 pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check second CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install second KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds2.example.com:3389 \
    -D pki_ds_base_dn=dc=kra,dc=pki2,dc=example,dc=com \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install second KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check second KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check second KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Rewrap archived keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "Secret.123" > password.txt

# export second KRA storage cert
docker exec pki2 pki-server cert-export kra_storage \
    --cert-file $SHARED/kra2_storage.crt

# rewrap archived keys using second KRA storage cert
docker exec pki1 KRATool \
    -kratool_config_file /usr/share/pki/tools/KRATool.cfg \
    -source_kra_naming_context dc=kra,dc=pki1,dc=example,dc=com \
    -source_pki_security_database_path /var/lib/pki/pki-tomcat/conf/alias \
    -source_pki_security_database_pwdfile $SHARED/password.txt \
    -source_storage_token_name "Internal Key Storage Token" \
    -source_storage_certificate_nickname kra_storage \
    -source_ldif_file $SHARED/kra1.ldif \
    -process_requests_and_key_records_only \
    -unwrap_algorithm AES \
    -target_ldif_file $SHARED/keys.ldif \
    -target_kra_naming_context dc=kra,dc=pki2,dc=example,dc=com \
    -target_storage_certificate_file $SHARED/kra2_storage.crt \
    -log_file $SHARED/kratool.log

cat kratool.log
cat keys.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Rewrap archived keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import keys into second KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ds2 ldapadd \
    -H ldap://ds2.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/keys.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import keys into second KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived key in second KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

DEC_KEY_ID=$(python -c "print(int('$KEY_ID', 16))")
echo "Dec Key ID: $DEC_KEY_ID"

# get key record
docker exec ds2 ldapsearch \
    -H ldap://ds2.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "cn=$DEC_KEY_ID,ou=keyRepository,ou=kra,dc=kra,dc=pki2,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL | tee kra2.ldif

# encryption mode should be "false" by default
echo "false" > expected
sed -n 's/^metaInfo: payloadEncrypted:\(.*\)$/\1/p' kra2.ldif > actual
diff expected actual

# key wrap algorithm should be "AES KeyWrap/Padding" by default
echo "AES KeyWrap/Padding" > expected
sed -n 's/^metaInfo: payloadWrapAlgorithm:\(.*\)$/\1/p' kra2.ldif > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived key in second KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key retrieval from second KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

BASE64_CERT=$(docker exec pki1 pki nss-cert-export --format DER testuser | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

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

# retrieve archived cert and key into PKCS #12 file
# https://github.com/dogtagpki/pki/wiki/Retrieving-Archived-Key
docker exec pki2 pki \
    -n caadmin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --output-data archived.p12

# import PKCS #12 file into NSS database
docker exec pki2 pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 archived.p12 \
    --password Secret.123

# remove archived cert from NSS database
docker exec pki2 pki -d nssdb nss-cert-del UID=testuser

# import original cert into NSS database
docker exec pki2 pki -d nssdb nss-cert-import --cert $SHARED/testuser.crt testuser

# the original cert should match the archived key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec pki2 pki -d nssdb nss-cert-show testuser | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key retrieval from second KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove first KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove first KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove first CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove first CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove second KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove second KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove second CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove second CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for first PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki1 ls -l
docker exec pki1 find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for first PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check first CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki1 find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check first CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check first KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki1 find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check first KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for second PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki2 ls -l
docker exec pki2 find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for second PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check second CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki2 find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check second CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check second KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki2 find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check second KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-migration-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-migration-test PASSED ===="
