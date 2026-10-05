#!/bin/bash
# Generated TMT port of .github/workflows/ca-profile-caDirPinUserCert-test.yml
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

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: jq libxml2-utils moreutils xmlstarlet
# Most are available in the pki-runner container or Fedora host.
command -v jq >/dev/null 2>&1 || dnf install -y jq 2>/dev/null || true
command -v libxml2-utils >/dev/null 2>&1 || dnf install -y libxml2-utils 2>/dev/null || true
command -v moreutils >/dev/null 2>&1 || dnf install -y moreutils 2>/dev/null || true
command -v xmlstarlet >/dev/null 2>&1 || dnf install -y xmlstarlet 2>/dev/null || true
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

step "Add LDAP users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: ou=people,dc=example,dc=com
objectclass: top
objectclass: organizationalUnit
ou: people
aci: (target="ldap:///ou=people,dc=example,dc=com")
 (targetattr=objectClass||dc||ou||uid||cn||sn||givenName)
 (version 3.0; acl "Allow anyone to read and search basic attributes"; allow (search, read) userdn = "ldap:///anyone";)
aci: (target="ldap:///ou=people,dc=example,dc=com")
 (targetattr=*)
 (version 3.0; acl "Allow anyone to read and search itself"; allow (search, read) userdn = "ldap:///self";)

dn: uid=testuser1,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser1
cn: Test User 1
sn: User
userPassword: Secret.123

dn: uid=testuser2,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser2
cn: Test User 2
sn: User
userPassword: Secret.123

dn: uid=testuser3,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser3
cn: Test User 3
sn: User
userPassword: Secret.123
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add LDAP users (rc=$_rc)" >&2
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

step "Set up PIN database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure setpin
docker exec pki sed \
    -e "s/^host=.*$/host=ds.example.com/" \
    -e "s/^port=.*$/port=3389/" \
    -e "s/^binddn=.*$/binddn=cn=Directory Manager/" \
    -e "s/^bindpw=.*$/bindpw=Secret.123/" \
    -e "s/^pinmanager=.*$/pinmanager=uid=pinmanager,dc=example,dc=com/" \
    -e "s/^pinmanagerpwd=.*$/pinmanagerpwd=Secret.123/" \
    -e "s/^basedn=.*$/basedn=ou=people,dc=example,dc=com/" \
    /usr/share/pki/tools/setpin.conf | tee setpin.conf

# run setpin
# NOTE: currently setpin will crash due to buffer overflow
# so the operations need to be executed manually instead
# docker exec pki setpin optfile=$SHARED/setpin.conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up PIN database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add PIN schema"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapmodify \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: cn=schema
changeType: modify
add: attributeTypes
attributeTypes: ( pin-oid NAME 'pin' DESC 'User Defined Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE X-ORIGIN ( 'custom for setpin' 'user defined' ) )
-
add: objectClasses
objectClasses: ( 2.16.840.1.117370.999.1.2.10 NAME 'pinPerson' DESC 'User Defined ObjectClass' SUP top STRUCTURAL MAY ( aci $ pin ) X-ORIGIN 'user defined' )
-
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add PIN schema (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add PIN manager"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: uid=pinmanager,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: pinmanager
cn: PIN Manager
sn: Manager
userPassword: Secret.123
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add PIN manager (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add PIN access control"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapmodify \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: ou=people,dc=example,dc=com
changeType: modify
add: aci
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr="pin")(version 3.0; acl "Pin attribute"; allow (all) userdn = "ldap:///uid=pinmanager,dc=example,dc=com"; deny(proxy,selfwrite,compare,add,write,delete,search) userdn = "ldap:///self";)
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr="objectclass")(version 3.0; acl "Pin Objectclass"; allow (all) userdn = "ldap:///uid=pinmanager,dc=example,dc=com";)
-
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add PIN access control (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PIN schema"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check pin attribute type
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    attributeTypes \
    | tee output

sed -n "/^attributeTypes:\s*(\s*\S\+\s*NAME\s*'pin'/p" output > actual

cat > expected << EOF
attributeTypes: ( pin-oid NAME 'pin' DESC 'User Defined Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE X-ORIGIN ( 'custom for setpin' 'user defined' ) )
EOF

diff expected actual

# check pinPerson object class
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses \
    | tee output

sed -n "/^objectClasses:\s*(\s*\S\+\s*NAME\s*'pinPerson'/p" output > actual

cat > expected << EOF
objectClasses: ( 2.16.840.1.117370.999.1.2.10 NAME 'pinPerson' DESC 'User Defined ObjectClass' SUP top STRUCTURAL MAY ( aci $ pin ) X-ORIGIN 'user defined' )
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PIN schema (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PIN manager"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=pinmanager,dc=example,dc=com" \
    -s base \
    -t \
    -o ldif_wrap=no \
    -LLL \
    | tee output

cat > expected << EOF
dn: uid=pinmanager,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: top
uid: pinmanager
cn: PIN Manager
sn: Manager
userPassword:: XXXXX
EOF

# normalize output
sed \
    -e '/^$/d' \
    -e 's/^\(userPassword\):: .*$/\1:: XXXXX/' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PIN manager (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PIN access control"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "ou=people,dc=example,dc=com" \
    -s base \
    -t \
    -o ldif_wrap=no \
    -LLL \
    aci \
    | tee output

# there should be 2 old ACI attrs and 2 new ones
cat > expected << EOF
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr=objectClass||dc||ou||uid||cn||sn||givenName)(version 3.0; acl "Allow anyone to read and search basic attributes"; allow (search, read) userdn = "ldap:///anyone";)
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr=*)(version 3.0; acl "Allow anyone to read and search itself"; allow (search, read) userdn = "ldap:///self";)
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr="pin")(version 3.0; acl "Pin attribute"; allow (all) userdn = "ldap:///uid=pinmanager,dc=example,dc=com"; deny(proxy,selfwrite,compare,add,write,delete,search) userdn = "ldap:///self";)
aci: (target="ldap:///ou=people,dc=example,dc=com")(targetattr="objectclass")(version 3.0; acl "Pin Objectclass"; allow (all) userdn = "ldap:///uid=pinmanager,dc=example,dc=com";)
EOF

grep '^aci:' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PIN access control (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate user PINs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# disable setup mode
sed -i "/^setup=/d" setpin.conf

# run setpin to generate PINs for all users
docker exec pki setpin \
    filter="(objectClass=person)" \
    optfile=$SHARED/setpin.conf \
    output=$SHARED/setpin.out \
    write

cat setpin.out

# check users
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "ou=people,dc=example,dc=com" \
    -s one \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate user PINs (rc=$_rc)" >&2
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

step "Configure PinDirEnrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-set auths.instance.PinDirEnrollment.pluginName UidPwdPinDirAuth
docker exec pki pki-server ca-config-set auths.instance.PinDirEnrollment.ldap.basedn ou=people,dc=example,dc=com
docker exec pki pki-server ca-config-set auths.instance.PinDirEnrollment.ldap.ldapauth.authtype BasicAuth
docker exec pki pki-server ca-config-set auths.instance.PinDirEnrollment.ldap.ldapconn.host ds.example.com
docker exec pki pki-server ca-config-set auths.instance.PinDirEnrollment.ldap.ldapconn.port 3389
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure PinDirEnrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable caDirPinUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki sed -i \
    -e "s/^\(enable\)=.*/\1=true/" \
    /var/lib/pki/pki-tomcat/ca/profiles/ca/caDirPinUserCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable caDirPinUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart CA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart CA subsystem (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
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
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check enrollment using pki ca-cert-issue"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
PIN=$(sed -En 'N; s/^dn:uid=testuser1,.*\npin:(.*)$/\1/p; D' setpin.out)
echo "PIN: $PIN"

# generate cert request
docker exec pki pki nss-cert-request \
    --subject "UID=testuser1" \
    --csr $SHARED/testuser1.csr

echo "Secret.123" > password.txt
echo "$PIN" > pin.txt

# issue cert
docker exec pki pki \
    ca-cert-issue \
    --profile caDirPinUserCert \
    --username testuser1 \
    --password-file $SHARED/password.txt \
    --pin-file $SHARED/pin.txt \
    --csr-file $SHARED/testuser1.csr \
    --output-file testuser1.crt

# import cert
docker exec pki pki nss-cert-import testuser1 --cert testuser1.crt
docker exec pki pki nss-cert-show testuser1 | tee output

# the cert should match the key (trust flags must be u,u,u)
echo "u,u,u" > expected
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check enrollment using pki ca-cert-issue (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check enrollment using XML"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
PIN=$(sed -En 'N; s/^dn:uid=testuser2,.*\npin:(.*)$/\1/p; D' setpin.out)
echo "PIN: $PIN"

# generate cert request
docker exec pki pki nss-cert-request \
    --subject "UID=testuser2" \
    --csr $SHARED/testuser2.csr

# retrieve request template using REST API v1
docker exec pki curl \
    -k \
    -s \
    -H "Content-Type: application/xml" \
    -H "Accept: application/xml" \
    https://pki.example.com:8443/ca/v1/certrequests/profiles/caDirPinUserCert \
    | xmllint --format - \
    | tee testuser2-request.xml

# insert username
xmlstarlet edit --inplace \
    -s "/CertEnrollmentRequest/Attributes" --type elem --name "Attribute" -v "testuser2" \
    -i "/CertEnrollmentRequest/Attributes/Attribute[not(@name)]" -t attr -n "name" -v "uid" \
    testuser2-request.xml

# insert password
xmlstarlet edit --inplace \
    -s "/CertEnrollmentRequest/Attributes" --type elem --name "Attribute" -v "Secret.123" \
    -i "/CertEnrollmentRequest/Attributes/Attribute[not(@name)]" -t attr -n "name" -v "pwd" \
    testuser2-request.xml

# insert PIN
xmlstarlet edit --inplace \
    -s "/CertEnrollmentRequest/Attributes" --type elem --name "Attribute" -v "$PIN" \
    -i "/CertEnrollmentRequest/Attributes/Attribute[not(@name)]" -t attr -n "name" -v "pin" \
    testuser2-request.xml

# insert request type
xmlstarlet edit --inplace \
    -u "/CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value" \
    -v "pkcs10" \
    testuser2-request.xml

# insert CSR
xmlstarlet edit --inplace \
    -u "/CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value" \
    -v "$(cat testuser2.csr)" \
    testuser2-request.xml

cat testuser2-request.xml

# submit request using REST API v1
docker exec pki curl \
    -k \
    -s \
    -X POST \
    -d @$SHARED/testuser2-request.xml \
    -H "Content-Type: application/xml" \
    -H "Accept: application/xml" \
    https://pki.example.com:8443/ca/v1/certrequests \
    | xmllint --format - \
    | tee testuser2-response.xml
CERT_ID=$(xmlstarlet sel -t -v '/CertRequestInfos/CertRequestInfo/certID' testuser2-response.xml)

# retrieve cert using REST API v1
docker exec pki curl \
    -k \
    -s \
    -H "Content-Type: application/xml" \
    -H "Accept: application/xml" \
    https://pki.example.com:8443/ca/v1/certs/$CERT_ID \
    | xmllint --format - \
    | tee testuser2-cert.xml

# The XML transformation in CertData.toXML() converts "\r"
# chars in the cert into "&#13;" which need to be removed.
# TODO: Fix CertData.toXML() to avoid adding "&#13;".
xmlstarlet sel -t -v '/CertData/Encoded' testuser2-cert.xml \
    | sed 's/&#13;$//' \
    | tee testuser2.crt

# import cert
docker exec pki pki nss-cert-import testuser2 --cert $SHARED/testuser2.crt
docker exec pki pki nss-cert-show testuser2 | tee output

# the cert should match the key (trust flags must be u,u,u)
echo "u,u,u" > expected
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check enrollment using XML (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check enrollment using JSON"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
PIN=$(sed -En 'N; s/^dn:uid=testuser3,.*\npin:(.*)$/\1/p; D' setpin.out)
echo "PIN: $PIN"

# generate cert request
docker exec pki pki nss-cert-request \
    --subject "UID=testuser3" \
    --csr $SHARED/testuser3.csr

# retrieve request template using REST API v2
docker exec pki curl \
    -k \
    -s \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    https://pki.example.com:8443/ca/v2/certrequests/profiles/caDirPinUserCert \
    | python -m json.tool \
    | tee testuser3-request.json

# insert username
jq '.Attributes.Attribute[.Attributes.Attribute|length] |= . + { "name": "uid", "value": "testuser3" }' \
    testuser3-request.json | sponge testuser3-request.json

# insert password
jq '.Attributes.Attribute[.Attributes.Attribute|length] |= . + { "name": "pwd", "value": "Secret.123" }' \
    testuser3-request.json | sponge testuser3-request.json

# insert PIN
jq --arg PIN "$PIN" '.Attributes.Attribute[.Attributes.Attribute|length] |= . + { "name": "pin", "value": $PIN }' \
    testuser3-request.json | sponge testuser3-request.json

# insert request type
jq '( .Input[].Attribute[] | select(.name=="cert_request_type") ).Value |= "pkcs10"' \
    testuser3-request.json | sponge testuser3-request.json

# insert CSR
jq --rawfile cert_request testuser3.csr '( .Input[].Attribute[] | select(.name=="cert_request") ).Value |= $cert_request' \
    testuser3-request.json | sponge testuser3-request.json

cat testuser3-request.json

# submit request using REST API v2
docker exec pki curl \
    -k \
    -s \
    -X POST \
    -d @$SHARED/testuser3-request.json \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    https://pki.example.com:8443/ca/v2/certrequests \
    | python -m json.tool \
    | tee testuser3-response.json
CERT_ID=$(jq -j '.entries[].certId' testuser3-response.json)

# retrieve cert using REST API v2
docker exec pki curl \
    -k \
    -s \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    https://pki.example.com:8443/ca/v2/certs/$CERT_ID \
    | python -m json.tool \
    | tee testuser3-cert.json
jq -j '.Encoded' testuser3-cert.json | tee testuser3.crt

# import cert
docker exec pki pki nss-cert-import testuser3 --cert $SHARED/testuser3.crt
docker exec pki pki nss-cert-show testuser3 | tee output

# the cert should match the key (trust flags must be u,u,u)
echo "u,u,u" > expected
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check enrollment using JSON (rc=$_rc)" >&2
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
    echo "==== ca-profile-caDirPinUserCert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-profile-caDirPinUserCert-test PASSED ===="
