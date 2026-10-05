#!/bin/bash
# Generated TMT port of .github/workflows/ca-publishing-crl-file-test.yml
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

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: libxml2-utils
# Most are available in the pki-runner container or Fedora host.
command -v libxml2-utils >/dev/null 2>&1 || dnf install -y libxml2-utils 2>/dev/null || true
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure caUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# remove AIA extension
docker exec pki sed -i \
    -e "s/^\(policyset.userCertSet.list\)=.*$/\1=1,10,2,3,4,6,7,8,9/" \
    -e "/^policyset.userCertSet.5/d" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg

# add CDP extension
URI="http://pki.example.com:8080/crl/MasterCRL.crl"
docker exec pki sed -i \
    -e "s/^\(policyset.userCertSet.list\)=\(.*\)$/\1=\2,11/" \
    -e "$ a policyset.userCertSet.11.constraint.class_id=noConstraintImpl" \
    -e "$ a policyset.userCertSet.11.constraint.name=No Constraint" \
    -e "$ a policyset.userCertSet.11.default.class_id=crlDistributionPointsExtDefaultImpl" \
    -e "$ a policyset.userCertSet.11.default.name=CRL Distribution Points Extension Default" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsCritical=false" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsNum=1" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsEnable_0=true" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsIssuerName_0=cn=CA Signing Certificate,ou=pki-tomcat,o=EXAMPLE" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsIssuerType_0=DirectoryName" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsPointName_0=$URI" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsPointType_0=URIName" \
    -e "$ a policyset.userCertSet.11.default.params.crlDistPointsReasons_0=" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure caUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure caServerCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# remove AIA extension
docker exec pki sed -i \
    -e "s/^\(policyset.serverCertSet.list\)=.*$/\1=1,2,3,4,6,7,8,12/" \
    -e "/^policyset.serverCertSet.5/d" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure caServerCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare CRL publishing location"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CRL folder
docker exec pki mkdir -p /var/lib/pki/pki-tomcat/crl
docker exec pki chown -R pkiuser:pkiuser /var/lib/pki/pki-tomcat/crl

# create CRL webapp config
# use allowLinking=true since MasterCRL.crl is a link
# use cachingAllowed=false since MasterCRL.crl is not static
cat > crl.xml << EOF
<Context docBase="/var/lib/pki/pki-tomcat/crl">
    <Resources allowLinking="true" cachingAllowed="false" />
</Context>
EOF

# deploy CRL webapp
docker cp crl.xml pki:/var/lib/pki/pki-tomcat/conf/Catalina/localhost
docker exec pki chown -R pkiuser:pkiuser /var/lib/pki/pki-tomcat/conf/Catalina/localhost/crl.xml
docker exec pki ls -l /var/lib/pki/pki-tomcat/conf/Catalina/localhost
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare CRL publishing location (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure file-based CRL publishing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure file-based CRL publisher
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.pluginName FileBasedPublisher
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.crlLinkExt crl
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.directory /var/lib/pki/pki-tomcat/crl
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.latestCrlLink true
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.timeStamp LocalTime
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.zipCRLs false
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.zipLevel 9
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.Filename.b64 false
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.FileBasedPublisher.Filename.der true

# configure CRL publishing rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.enable true
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.mapper NoMap
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.pluginName Rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.predicate ""
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.publisher FileBasedPublisher
docker exec pki pki-server ca-config-set ca.publish.rule.instance.FileCrlRule.type crl

# enable CRL publishing
docker exec pki pki-server ca-config-set ca.publish.enable true

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
    echo "FAIL: Configure file-based CRL publishing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki openssl x509 -text -noout -in ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_ocsp_signing --cert-file ca_ocsp_signing.crt
docker exec pki openssl x509 -text -noout -in ca_ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_audit_signing --cert-file ca_audit_signing.crt
docker exec pki openssl x509 -text -noout -in ca_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export subsystem --cert-file subsystem.crt
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
docker exec pki pki-server cert-export sslserver --cert-file sslserver.crt
docker exec pki openssl x509 -text -noout -in sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
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
    docker exec pki pki-healthcheck --failures-only
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

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
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

step "Create user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# request user cert
docker exec pki pki client-cert-request uid=testuser | tee output

USER_REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "USER_REQUEST_ID: $USER_REQUEST_ID"

# issue user cert
docker exec pki pki -n caadmin ca-cert-request-approve $USER_REQUEST_ID --force | tee output

USER_CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "USER_CERT_ID: $USER_CERT_ID"
echo $USER_CERT_ID > user-cert.id

# check user cert status
docker exec pki pki ca-cert-show $USER_CERT_ID | tee output

# user cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual

# check user cert extensions
docker exec pki pki ca-cert-export $USER_CERT_ID --output-file testuser.crt
docker exec pki openssl x509 -text -noout -in testuser.crt | tee output

# user cert should have a CDP extension
echo "X509v3 CRL Distribution Points: " > expected
echo "URI:http://pki.example.com:8080/crl/MasterCRL.crl" >> expected
sed -En '1N;$!N;s/^ *(X509v3 CRL Distribution Points:.*)\n.*\n *(\S*).*$/\1\n\2/p;D' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# request server cert
docker exec pki pki client-cert-request --profile caServerCert cn=test.example.com | tee output

SERVER_REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "SERVER_REQUEST_ID: $SERVER_REQUEST_ID"

# issue server cert
docker exec pki pki -n caadmin ca-cert-request-approve $SERVER_REQUEST_ID --force | tee output

SERVER_CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "SERVER_CERT_ID: $SERVER_CERT_ID"
echo $SERVER_CERT_ID > server-cert.id

# check server cert status
docker exec pki pki ca-cert-show $SERVER_CERT_ID | tee output

# server cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual

# check server cert extensions
docker exec pki pki ca-cert-export $SERVER_CERT_ID --output-file test.example.com.crt
docker exec pki openssl x509 -text -noout -in test.example.com.crt | tee output

# server cert should not have a CDP extension
sed -En 's/^ *(X509v3 CRL Distribution Points:.*)$/\1/p' output > actual
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial CRL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check CRL files
docker exec pki ls -l /var/lib/pki/pki-tomcat/crl | tee output

# there should be no CRL files initially
echo "total 0" > expected
diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CRL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after update"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# force CRL update
docker exec pki pki -n caadmin ca-crl-update

# wait for CRL update
sleep 10

# check CRL files
docker exec pki find /var/lib/pki/pki-tomcat/crl -name "MasterCRL-*.der" | tee output

# there should be one timestamped CRL file
cat output | wc -l > actual
echo "1" > expected
diff expected actual

# check the latest CRL
docker exec pki openssl crl \
    -in /var/lib/pki/pki-tomcat/crl/MasterCRL.crl \
    -inform DER \
    -text \
    -noout | tee output

# CRL should contain no certs
sed -n "s/^\s*\(Serial Number:.*\)\s*$/\1/p" output | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after update (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user cert after update"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check user cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -crl_download \
    -CAfile ca_signing.crt \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be valid
echo "testuser.crt: OK" > expected
diff expected stdout

# check user cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 0 \
    -pp \
    -g leaf \
    -m crl \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be valid
echo "Chain is good!" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user cert after update (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check server cert after update"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# download the latest CRL
docker exec pki curl -sJO http://pki.example.com:8080/crl/MasterCRL.crl

# convert CRL to PEM
docker exec pki openssl crl \
    -in MasterCRL.crl \
    -inform DER \
    -out MasterCRL.pem \
    -outform PEM

# check server cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -CRLfile MasterCRL.pem \
    -CAfile ca_signing.crt \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be valid
echo "test.example.com.crt: OK" > expected
diff expected stdout

# import CRL into NSS
docker exec pki crlutil -I -d /root/.dogtag/nssdb -i MasterCRL.crl
docker exec pki crlutil -L -d /root/.dogtag/nssdb -n ca_signing

# check server cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 1 \
    -p \
    -g leaf \
    -m crl \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be valid
echo "Chain is good!" > expected
diff expected stderr

# remove CRL from NSS
docker exec pki crlutil -D -d /root/.dogtag/nssdb -n ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check server cert after update (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
USER_CERT_ID=$(cat user-cert.id)
docker exec pki pki -n caadmin ca-cert-hold $USER_CERT_ID --force

docker exec pki pki ca-cert-show $USER_CERT_ID | tee output

# user cert should be revoked
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
SERVER_CERT_ID=$(cat server-cert.id)
docker exec pki pki -n caadmin ca-cert-hold $SERVER_CERT_ID --force

docker exec pki pki ca-cert-show $SERVER_CERT_ID | tee output

# server cert should be revoked
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check CRL files
docker exec pki find /var/lib/pki/pki-tomcat/crl -name "MasterCRL-*.der" | sort | tee output

# there should be two timestamped CRL files
cat output | wc -l > actual
echo "3" > expected
diff expected actual

# check the latest CRL
docker exec pki openssl crl \
    -in /var/lib/pki/pki-tomcat/crl/MasterCRL.crl \
    -inform DER \
    -text \
    -noout | tee output

# CRL should contain two certs
sed -n "s/^\s*\(Serial Number:.*\)\s*$/\1/p" output | wc -l > actual
echo "2" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user cert after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check user cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -crl_download \
    -CAfile ca_signing.crt \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be invalid
echo "UID=testuser" > expected
echo "error 23 at 0 depth lookup: certificate revoked" >> expected
echo "error testuser.crt: verification failed" >> expected
diff expected stderr

# check user cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 0 \
    -pp \
    -g leaf \
    -m crl \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be invalid
echo "Chain is bad!" > expected
head -1 stderr > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user cert after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check server cert after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# download the latest CRL
docker exec pki curl -sJO http://pki.example.com:8080/crl/MasterCRL.crl

# convert CRL to PEM
docker exec pki openssl crl \
    -in MasterCRL.crl \
    -inform DER \
    -out MasterCRL.pem \
    -outform PEM

# check server cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -CRLfile MasterCRL.pem \
    -CAfile ca_signing.crt \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be invalid
echo "CN=test.example.com" > expected
echo "error 23 at 0 depth lookup: certificate revoked" >> expected
echo "error test.example.com.crt: verification failed" >> expected
diff expected stderr

# import CRL into NSS
docker exec pki crlutil -I -d /root/.dogtag/nssdb -i MasterCRL.crl
docker exec pki crlutil -L -d /root/.dogtag/nssdb -n ca_signing

# check server cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 1 \
    -p \
    -g leaf \
    -m crl \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be invalid
echo "Chain is bad!" > expected
head -1 stderr > actual
diff expected actual

# remove CRL from NSS
docker exec pki crlutil -D -d /root/.dogtag/nssdb -n ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check server cert after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unrevoke user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# unrevoke user cert
USER_CERT_ID=$(cat user-cert.id)
docker exec pki pki -n caadmin ca-cert-release-hold $USER_CERT_ID --force

docker exec pki pki ca-cert-show $USER_CERT_ID | tee output

# user cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unrevoke server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# unrevoke server cert
SERVER_CERT_ID=$(cat server-cert.id)
docker exec pki pki -n caadmin ca-cert-release-hold $SERVER_CERT_ID --force

docker exec pki pki ca-cert-show $SERVER_CERT_ID | tee output

# server cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check CRL files
docker exec pki find /var/lib/pki/pki-tomcat/crl -name "MasterCRL-*.der" | sort | tee output

# there should be three timestamped CRL files
cat output | wc -l > actual
echo "5" > expected
diff expected actual

# check the latest CRL
docker exec pki openssl crl \
    -in /var/lib/pki/pki-tomcat/crl/MasterCRL.crl \
    -inform DER \
    -text \
    -noout | tee output

# CRL should contain no certs
sed -n "s/^\s*\(Serial Number:.*\)\s*$/\1/p" output | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after unrevocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user cert after unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check user cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -crl_download \
    -CAfile ca_signing.crt \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be valid
echo "testuser.crt: OK" > expected
diff expected stdout

# check user cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 0 \
    -pp \
    -g leaf \
    -m crl \
    testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# user cert should be valid
echo "Chain is good!" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user cert after unrevocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check server cert after unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# download the latest CRL
docker exec pki curl -sJO http://pki.example.com:8080/crl/MasterCRL.crl

# convert CRL to PEM
docker exec pki openssl crl \
    -in MasterCRL.crl \
    -inform DER \
    -out MasterCRL.pem \
    -outform PEM

# check server cert using OpenSSL
docker exec pki openssl verify \
    -crl_check \
    -CRLfile MasterCRL.pem \
    -CAfile ca_signing.crt \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be valid
echo "test.example.com.crt: OK" > expected
diff expected stdout

# import CRL into NSS
docker exec pki crlutil -I -d /root/.dogtag/nssdb -i MasterCRL.crl
docker exec pki crlutil -L -d /root/.dogtag/nssdb -n ca_signing

# check server cert using NSS
docker exec pki /usr/lib64/nss/unsupported-tools/vfychain \
    -d /root/.dogtag/nssdb \
    -a \
    -u 1 \
    -p \
    -g leaf \
    -m crl \
    test.example.com.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# server cert should be valid
echo "Chain is good!" > expected
diff expected stderr

# remove CRL from NSS
docker exec pki crlutil -D -d /root/.dogtag/nssdb -n ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check server cert after unrevocation (rc=$_rc)" >&2
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
    echo "==== ca-publishing-crl-file-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-publishing-crl-file-test PASSED ===="
