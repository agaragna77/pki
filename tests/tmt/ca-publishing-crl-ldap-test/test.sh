#!/bin/bash
# Generated TMT port of .github/workflows/ca-publishing-crl-ldap-test.yml
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

step "Prepare CRL publishing subtree"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki ldapadd \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: dc=crl,dc=pki,dc=example,dc=com
objectClass: domain
dc: crl
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare CRL publishing subtree (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CRL publishing"
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

# configure LDAP-based CRL publisher
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlAttr "certificateRevocationList;binary"
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlObjectClass pkiCA
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.pluginName LdapCrlPublisher

# configure CRL mapper
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.createCAEntry true
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.pluginName LdapCaSimpleMap

# configure CRL publishing rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.enable true
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.mapper LdapCrlMap
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.pluginName Rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.predicate ""
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.publisher LdapCrlPublisher
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.type crl

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
    echo "FAIL: Configure CRL publishing (rc=$_rc)" >&2
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

step "Initialize PKI client"
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

docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-create.sh
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-create.sh
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize PKI client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial CRL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check CRL LDAP entries
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" | tee output

# there should be no CRL attributes
{ grep "certificateRevocationList;binary:" output || true; } | wc -l > actual
echo "0" > expected
diff expected actual
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

# check CRL LDAP entries
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" | tee output

# there should be one CRL attribute
{ grep "certificateRevocationList;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the latest CRL
docker exec pki openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout | tee output

# there should be no certs in the latest CRL
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

step "Check CRL after cert revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-revoke.sh

# check CRL LDAP entries
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" | tee output

# there should be one CRL attribute
{ grep "certificateRevocationList;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the latest CRL
docker exec pki openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout | tee output

# there should be one cert in the latest CRL
sed -n "s/^\s*\(Serial Number:.*\)\s*$/\1/p" output | wc -l > actual
echo "1" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after cert revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after cert unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki /usr/share/pki/tests/ca/bin/ca-agent-cert-unrevoke.sh

# check CRL LDAP entries
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" | tee output

# there should be one CRL attribute
{ grep "certificateRevocationList;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# check the latest CRL
docker exec pki openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout | tee output

# there should be no certs in the latest CRL
sed -n "s/^\s*\(Serial Number:.*\)\s*$/\1/p" output | wc -l > actual
echo "0" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after cert unrevocation (rc=$_rc)" >&2
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
    echo "==== ca-publishing-crl-ldap-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-publishing-crl-ldap-test PASSED ===="
