#!/bin/bash
# Generated TMT port of .github/workflows/ca-cmc-shared-token-test.yml
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

# disable audit event filters
docker exec pki pki-server ca-config-unset log.instance.SignedAudit.filters.CMC_USER_SIGNED_REQUEST_SIG_VERIFY
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
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create issuance protection cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate cert request
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-request \
    --subject "CN=CA Issuance Protection" \
    --csr ca_issuance_protection.csr

# check generated CSR
docker exec pki openssl req -text -noout -in ca_issuance_protection.csr

# create CMC request
docker exec pki CMCRequest \
    /usr/share/pki/server/examples/cmc/ca_issuance_protection-cmc-request.cfg \

# submit CMC request
docker exec pki HttpClient \
    /usr/share/pki/server/examples/cmc/ca_issuance_protection-cmc-submit.cfg \

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec pki CMCResponse \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -i ca_issuance_protection.cmc-response \
    -o ca_issuance_protection.p7b | tee output

echo "SUCCESS" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual

# check issued cert chain
docker exec pki openssl pkcs7 \
    -print_certs \
    -in ca_issuance_protection.p7b

# import cert chain
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    pkcs7-import \
    --pkcs7 ca_issuance_protection.p7b \
    ca_issuance_protection

# check imported cert chain
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-find

# configure issuance protection nickname
docker exec pki pki-server ca-config-set ca.cert.issuance_protection.nickname ca_issuance_protection
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create issuance protection cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure shared token auth"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# update schema
docker exec pki ldapmodify \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/ca/auth/ds/schema.ldif

# add user subtree
docker exec pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/ca/auth/ds/create.ldif

# add user records
docker exec pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/ca/auth/ds/example.ldif

# configure CMC shared token authentication
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.basedn ou=people,dc=example,dc=com
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapauth.authtype BasicAuth
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapauth.bindPWPrompt "Rule SharedToken"
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapconn.host ds.example.com
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapconn.port 3389
docker exec pki pki-server ca-config-set auths.instance.SharedToken.ldap.ldapconn.secureConn false
docker exec pki pki-server ca-config-set auths.instance.SharedToken.pluginName SharedToken
docker exec pki pki-server ca-config-set auths.instance.SharedToken.shrTokAttr shrTok

# enable caFullCMCSharedTokenCert profile
docker exec pki sed -i \
    -e "s/^\(enable\)=.*/\1=true/" \
    /var/lib/pki/pki-tomcat/ca/profiles/ca/caFullCMCSharedTokenCert.cfg

# enable caFullCMCUserSignedCert profile
docker exec pki sed -i \
    -e "s/^\(enable\)=.*/\1=true/" \
    /var/lib/pki/pki-tomcat/ca/profiles/ca/caFullCMCUserSignedCert.cfg

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure shared token auth (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate shared token for user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate shared token
docker exec pki CMCSharedToken \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -p Secret.123 \
    -n ca_issuance_protection \
    -s Secret.123 \
    -o $SHARED/testuser.b64

# convert into a single line
sed -e :a -e 'N;s/\r\n//;ba' testuser.b64 > token.txt
SHARED_TOKEN=$(cat token.txt)
echo "SHARED_TOKEN: $SHARED_TOKEN"

cat > add.ldif << EOF
dn: uid=testuser,ou=people,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: extensibleobject
-
add: shrTok
shrTok: $SHARED_TOKEN
-
EOF
cat add.ldif

# add shared token into user record
docker exec pki ldapmodify \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/add.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate shared token for user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue user cert with shared token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create key
docker exec pki pki nss-key-create --output-format json | tee output
KEY_ID=$(jq -r '.keyId' output)
echo "KEY_ID: $KEY_ID"

# generated cert request
docker exec pki pki \
    nss-cert-request \
    --key-id $KEY_ID \
    --subject "uid=testuser" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser.csr

# check generated CSR
docker exec pki openssl req -text -noout -in testuser.csr

# insert key ID into CMCRequest config
docker cp \
    pki:/usr/share/pki/tools/examples/cmc/testuser-cmc-request.cfg \
    testuser-cmc-request.cfg
sed -i \
    -e "s/^\(request.privKeyId\)=.*/\1=$KEY_ID/" \
    testuser-cmc-request.cfg
cat testuser-cmc-request.cfg

# create CMC request
docker exec pki CMCRequest \
    $SHARED/testuser-cmc-request.cfg

# submit CMC request
docker exec pki HttpClient \
    /usr/share/pki/tools/examples/cmc/testuser-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec pki CMCResponse \
    -d /root/.dogtag/nssdb \
    -i testuser.cmc-response \
    -o testuser.p7b | tee output

echo "SUCCESS" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual

# check issued cert chain
docker exec pki pki \
    pkcs7-cert-find \
    --pkcs7 testuser.p7b

# import cert chain
docker exec pki pki \
    pkcs7-import \
    --pkcs7 testuser.p7b \
    testuser

# check imported user cert
docker exec pki pki nss-cert-show testuser | tee output

# get user cert serial number
sed -n 's/^ *Serial Number: *\(.*\)/\1/p' output > testuser.serial
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue user cert with shared token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke user cert with shared token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HEX_SERIAL=$(cat testuser.serial)
echo "Hex serial: $HEX_SERIAL"

DEC_SERIAL=$(python -c "print(int('$HEX_SERIAL', 16))")
echo "Dec serial: $DEC_SERIAL"

SHARED_TOKEN=$(cat token.txt)

cat > modify.ldif << EOF
dn: cn=$DEC_SERIAL,ou=certificateRepository,ou=ca,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: metaInfo
metaInfo: revShrTok:$SHARED_TOKEN
-
EOF
cat modify.ldif

# add shared token into cert record
docker exec pki ldapmodify \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/modify.ldif

# insert user cert serial number into CMCRequest config
docker cp \
    pki:/usr/share/pki/tools/examples/cmc/testuser-cmc-revocation-request.cfg \
    testuser-cmc-revocation-request.cfg
sed -i \
    -e "s/^\(revRequest.serial\)=.*/\1=$HEX_SERIAL/" \
    testuser-cmc-revocation-request.cfg
cat testuser-cmc-revocation-request.cfg

# create CMC request
docker exec pki CMCRequest \
    $SHARED/testuser-cmc-revocation-request.cfg

# submit CMC request
docker exec pki HttpClient \
    /usr/share/pki/tools/examples/cmc/testuser-cmc-revocation-submit.cfg

# process CMC response
docker exec pki CMCResponse \
    -d /root/.dogtag/nssdb \
    -i testuser.cmc-revocation-response | tee output

echo "SUCCESS" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual

# check cert status
docker exec pki pki ca-cert-show $HEX_SERIAL | tee output

echo "REVOKED" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke user cert with shared token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CMC_USER_SIGNED_REQUEST_SIG_VERIFY events"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki grep \
    "\[AuditEvent=CMC_USER_SIGNED_REQUEST_SIG_VERIFY\]" \
    /var/lib/pki/pki-tomcat/logs/ca/signedAudit/ca_audit | tee output

# there should be 1 event from user cert enrollment
echo "1" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CMC_USER_SIGNED_REQUEST_SIG_VERIFY events (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CERT_STATUS_CHANGE_REQUEST_PROCESSED events"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki grep \
    "\[AuditEvent=CERT_STATUS_CHANGE_REQUEST_PROCESSED\]" \
    /var/lib/pki/pki-tomcat/logs/ca/signedAudit/ca_audit | tee output

# there should be 1 event from user cert revocation
echo "1" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CERT_STATUS_CHANGE_REQUEST_PROCESSED events (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CMC_REQUEST_RECEIVED events"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki grep \
    "\[AuditEvent=CMC_REQUEST_RECEIVED\]" \
    /var/lib/pki/pki-tomcat/logs/ca/signedAudit/ca_audit | tee output

# there should be 3 events from issuance protection cert enrollment,
# user cert enrollment, user cert revocation
echo "3" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CMC_REQUEST_RECEIVED events (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CMC_RESPONSE_SENT events"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki grep \
    "\[AuditEvent=CMC_RESPONSE_SENT\]" \
    /var/lib/pki/pki-tomcat/logs/ca/signedAudit/ca_audit | tee output

# there should be 3 events from issuance protection cert enrollment,
# user cert enrollment, user cert revocation
echo "3" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CMC_RESPONSE_SENT events (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-cmc-shared-token-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-cmc-shared-token-test PASSED ===="
