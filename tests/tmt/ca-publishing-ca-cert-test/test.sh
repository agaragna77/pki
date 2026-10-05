#!/bin/bash
# Generated TMT port of .github/workflows/ca-publishing-ca-cert-test.yml
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

step "Export CA cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki openssl x509 \
    -in ca_signing.crt \
    -text \
    -noout | tee ca_signing.txt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export CA cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare CA cert publishing subtree"
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
    echo "FAIL: Prepare CA cert publishing subtree (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing"
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

# configure LDAP-based CA cert publisher
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr "cACertificate;binary"
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass pkiCA
docker exec pki pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.pluginName LdapCaCertPublisher

# configure CA cert mapper
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.createCAEntry true
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec pki pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.pluginName LdapCaSimpleMap

# configure CA cert publishing rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.enable true
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.mapper LdapCaCertMap
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.pluginName Rule
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.predicate ""
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.publisher LdapCaCertPublisher
docker exec pki pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.type cacert

# enable publishing
docker exec pki pki-server ca-config-set ca.publish.enable true

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check published CA cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" | tee output

# there should be one CA cert attribute
{ grep "cACertificate;binary:" output || true; } | wc -l > actual
echo "1" > expected
diff expected actual

FILENAME=$(sed -n 's/cACertificate;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

# compare exported and published CA certs
docker exec pki openssl x509 \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout | tee output
diff ca_signing.txt output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check published CA cert (rc=$_rc)" >&2
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
    echo "==== ca-publishing-ca-cert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-publishing-ca-cert-test PASSED ===="
