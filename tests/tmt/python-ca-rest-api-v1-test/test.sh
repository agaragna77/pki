#!/bin/bash
# Generated TMT port of .github/workflows/python-ca-rest-api-v1-test.yml
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
    docker rm -f ca client ds 2>/dev/null || true
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
# Packages needed: podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v podman-docker >/dev/null 2>&1 || dnf install -y podman-docker 2>/dev/null || true
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

step "Set up client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=client.example.com \
    --network=example \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir certs

docker exec client pki \
    nss-cert-request \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/certs/ca_signing.csr

docker exec client pki \
    nss-cert-issue \
    --csr $SHARED/certs/ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert $SHARED/certs/ca_signing.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec client pki \
    nss-cert-show \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --csr $SHARED/certs/ocsp_signing.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/certs/ocsp_signing.csr \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --cert $SHARED/certs/ocsp_signing.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/ocsp_signing.crt \
    ocsp_signing

docker exec client pki \
    nss-cert-show \
    ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --csr $SHARED/certs/audit_signing.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/certs/audit_signing.csr \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    --cert $SHARED/certs/audit_signing.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/audit_signing.crt \
    --trust ,,P \
    audit_signing

docker exec client pki \
    nss-cert-show \
    audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/certs/subsystem.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/certs/subsystem.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/subsystem.crt \
    subsystem

docker exec client pki \
    nss-cert-show \
    subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=ca.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/certs/sslserver.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/certs/sslserver.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/sslserver.crt \
    sslserver

docker exec client pki \
    nss-cert-show \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/certs/admin.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/certs/admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert $SHARED/certs/admin.crt

docker exec client pki \
    nss-cert-import \
    --cert $SHARED/certs/admin.crt \
    admin

docker exec client pki \
    nss-cert-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export system certs and keys to PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/certs/server.p12 \
    --password Secret.123 \
    ca_signing \
    ocsp_signing \
    audit_signing \
    subsystem \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export system certs and keys to PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export admin cert and key to PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/certs/admin.p12 \
    --password Secret.123 \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export admin cert and key to PKCS #12 file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export admin key to PEM file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl pkcs12 \
   -in $SHARED/certs/admin.p12 \
   -passin pass:Secret.123 \
   -out $SHARED/certs/admin.key \
   -nodes \
   -nocerts
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export admin key to PEM file (rc=$_rc)" >&2
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

step "Configure DS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/base/server/database/ds/config.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure DS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add PKI schema"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ds ldapmodify \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/base/server/database/ds/schema.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add PKI schema (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA base entry"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: dc=ca,dc=pki,dc=example,dc=com
objectClass: dcObject
dc: ca
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA base entry (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA database entries"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sed \
    -e 's/{rootSuffix}/dc=ca,dc=pki,dc=example,dc=com/g' \
    base/ca/database/ds/create.ldif \
    | tee create.ldif
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/create.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA database entries (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sed \
    -e 's/{database}/userroot/g' \
    base/ca/database/ds/index.ldif \
    | tee index.ldif
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/index.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Rebuild CA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# start rebuild task
sed \
    -e 's/{database}/userroot/g' \
    base/ca/database/ds/indextasks.ldif \
    | tee indextasks.ldif
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/indextasks.ldif

# wait for task to complete
while true; do
    sleep 1

    docker exec ds ldapsearch \
        -H ldap://ds.example.com:3389 \
        -D "cn=Directory Manager" \
        -w Secret.123 \
        -b "cn=index1160589770, cn=index, cn=tasks, cn=config" \
        -LLL \
        nsTaskExitCode \
        | tee output

    sed -n -e 's/nsTaskExitCode:\s*\(.*\)/\1/p' output > nsTaskExitCode
    cat nsTaskExitCode

    if [ -s nsTaskExitCode ]; then
        break
    fi
done

echo "0" > expected
diff expected nsTaskExitCode
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Rebuild CA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA ACL resources"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sed \
    -e 's/{rootSuffix}/dc=ca,dc=pki,dc=example,dc=com/g' \
    base/ca/database/ds/acl.ldif \
    | tee acl.ldif
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f $SHARED/acl.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA ACL resources (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: cmsuser
cn: admin
sn: admin
uid: admin
mail: admin@example.com
userPassword: Secret.123
userState: 1
userType: adminType
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign admin cert to admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# convert cert from PEM to DER
openssl x509 -outform der -in certs/admin.crt -out certs/admin.der

# get serial number
openssl x509 -text -noout -in certs/admin.crt | tee output
SERIAL=$(sed -En 'N; s/^ *Serial Number:\n *(.*)$/\1/p; D' output)
echo "SERIAL: $SERIAL"
HEX_SERIAL=$(echo "$SERIAL" | tr -d ':')
echo "HEX_SERIAL: $HEX_SERIAL"
DEC_SERIAL=$(python -c "print(int('$HEX_SERIAL', 16))")
echo "DEC_SERIAL: $DEC_SERIAL"

docker exec -i ds ldapmodify \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: description
description: 2;$DEC_SERIAL;CN=CA Signing Certificate;CN=Administrator
-
add: userCertificate
userCertificate:< file:$SHARED/certs/admin.der
-
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign admin cert to admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add admin user into CA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapmodify \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: cn=Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Certificate Manager Agents,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Security Domain Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise CA Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise KRA Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise RA Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise TKS Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise OCSP Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-

dn: cn=Enterprise TPS Administrators,ou=groups,dc=ca,dc=pki,dc=example,dc=com
changetype: modify
add: uniqueMember
uniqueMember: uid=admin,ou=people,dc=ca,dc=pki,dc=example,dc=com
-
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add admin user into CA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create PKI CA 11.4 Dockerfile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create a new Dockerfile to disable access log buffer
cat > Dockerfile-pki-ca-11.4 <<EOF
FROM quay.io/dogtagpki/pki-ca:11.4 AS pki-ca-11.4

RUN dnf install -y xmlstarlet

RUN cat /etc/tomcat/server.xml
RUN xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/tomcat/server.xml
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI CA 11.4 Dockerfile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Build PKI CA 11.4 image"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker/build-push-action — translated to docker build
docker build -f Dockerfile-pki-ca-11.4 -t pki-ca:11.4 .
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Build PKI CA 11.4 image (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create PKI CA 11.4 container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name ca \
    --hostname=ca.example.com \
    --network=example \
    --network-alias=ca.example.com \
    -v $PWD/certs:/certs \
    --detach \
    pki-ca:11.4
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI CA 11.4 container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for CA container to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for CA container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/bin/pki-info.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -2 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Find CA cert request templates"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/ca/bin/pki-ca-cert-request-template-find.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
GET /ca/rest/certrequests/profiles HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find CA cert request templates (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Show CA cert request template"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/ca/bin/pki-ca-cert-request-template-show.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    -v \
    caServerCert

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
GET /ca/rest/certrequests/profiles/caServerCert HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Show CA cert request template (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA cert requests"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/ca/bin/pki-ca-cert-request-find.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    --client-cert $SHARED/certs/admin.crt \
    --client-key $SHARED/certs/admin.key \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
GET /ca/rest/account/login HTTP/1.1 200 admin
GET /ca/rest/agent/certrequests HTTP/1.1 200 admin
GET /ca/rest/account/logout HTTP/1.1 204 admin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA cert requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/ca/bin/pki-ca-cert-find.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
POST /ca/rest/certs/search HTTP/1.1 200 -
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client python /usr/share/pki/tests/ca/bin/pki-ca-user-find.py \
    -U https://ca.example.com:8443 \
    --ca-bundle $SHARED/certs/ca_signing.crt \
    --client-cert $SHARED/certs/admin.crt \
    --client-key $SHARED/certs/admin.key \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec ca find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default, then fall back to v1
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 404 -
GET /pki/rest/info HTTP/1.1 200 -
GET /ca/rest/account/login HTTP/1.1 200 admin
GET /ca/rest/admin/users HTTP/1.1 200 admin
GET /ca/rest/account/logout HTTP/1.1 204 admin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA users (rc=$_rc)" >&2
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

step "Check PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== python-ca-rest-api-v1-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== python-ca-rest-api-v1-test PASSED ===="
