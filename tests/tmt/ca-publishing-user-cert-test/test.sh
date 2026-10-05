#!/bin/bash
# Generated TMT port of .github/workflows/ca-publishing-user-cert-test.yml
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
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare publishing subtree"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: ou=people,dc=pki,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=testuser1,ou=people,dc=pki,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser1
cn: Test User 1
sn: User 1

dn: uid=testuser2,ou=people,dc=pki,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser2
cn: Test User 2
sn: User 2
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare publishing subtree (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure user cert publishing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP connection
docker exec pki pki-server ca-config-set ca.publish.ldappublish.enable true
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.authtype BasicAuth
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt internaldb
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.host ds.example.com
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.port 3389
docker exec pki pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.secureConn false

# configure LDAP-based user cert publisher
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapUserCertPublisher.certAttr "userCertificate;binary"
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapUserCertPublisher.pluginName LdapUserCertPublisher

# configure user cert mapper
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapUserCertMap.dnPattern "uid=\$subj.UID,ou=people,dc=pki,dc=example,dc=com"
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapUserCertMap.pluginName LdapSimpleMap

# configure user cert publishing rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.enable true
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.mapper LdapUserCertMap
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.pluginName Rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.predicate ""
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.publisher LdapUserCertPublisher
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapUserCertRule.type certs

# enable publishing
docker exec pki pki-server ca-config-set ca.publish.enable true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure user cert publishing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure caUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 1 minute
VALIDITY_DEFAULT="policyset.userCertSet.2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=1/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
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

step "Configure cert status update task"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure task to run every minute
docker exec pki pki-server ca-config-set ca.certStatusUpdateInterval 60
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure cert status update task (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure unpublish expired job to run automatically"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure job to run every minute
docker exec pki pki-server ca-config-set jobsScheduler.enabled true
docker exec pki pki-server ca-config-set jobsScheduler.job.unpublishExpiredCerts.cron "* * * * *"
docker exec pki pki-server ca-config-set jobsScheduler.job.unpublishExpiredCerts.enabled true
docker exec pki pki-server ca-config-set jobsScheduler.job.unpublishExpiredCerts.summary.enabled false
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure unpublish expired job to run automatically (rc=$_rc)" >&2
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

step "Check user 1 before enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser1,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be no cert attributes
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 1 before enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request uid=testuser1 | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > cert.id

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 1 after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser1,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be one cert attribute
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/userCertificate;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the cert
docker exec pki openssl x509 \
    -in "$FILENAME" \
    -inform DER \
    -text -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 1 after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
docker exec pki pki -n caadmin ca-cert-hold $CERT_ID --force

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be revoked
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 1 after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser1,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be no cert attributes
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 1 after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unrevoke user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
docker exec pki pki -n caadmin ca-cert-release-hold $CERT_ID --force

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid again
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 1 after unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser1,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be one cert attribute
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/userCertificate;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the cert
docker exec pki openssl x509 \
    -in "$FILENAME" \
    -inform DER \
    -text -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 1 after unrevocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for user 1 cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120

CERT_ID=$(cat cert.id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be expired
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "EXPIRED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for user 1 cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 1 after expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser1,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be no cert attributes
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 1 after expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure unpublish expired job to run manually"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-unset jobsScheduler.job.unpublishExpiredCerts.cron
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure unpublish expired job to run manually (rc=$_rc)" >&2
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

step "Check user 2 before enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser2,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be no cert attributes
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 2 before enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll user 2 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request uid=testuser2 | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > cert.id

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll user 2 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 2 after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser2,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be one cert attribute
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/userCertificate;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the cert
docker exec pki openssl x509 \
    -in "$FILENAME" \
    -inform DER \
    -text -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 2 after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for user 2 cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120

CERT_ID=$(cat cert.id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be expired
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "EXPIRED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for user 2 cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 2 after expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser2,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should still be one cert attribute
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/userCertificate;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the cert
docker exec pki openssl x509 \
    -in "$FILENAME" \
    -inform DER \
    -text -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 2 after expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run unpublish job manually"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-job-start unpublishExpiredCerts
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run unpublish job manually (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user 2 after manual execution"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 10

docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "uid=testuser2,ou=people,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t | tee output

# there should be no cert attributes
{ grep "userCertificate;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user 2 after manual execution (rc=$_rc)" >&2
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
    echo "==== ca-publishing-user-cert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-publishing-user-cert-test PASSED ===="
