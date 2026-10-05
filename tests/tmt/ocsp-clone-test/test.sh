#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-clone-test.yml
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
    docker rm -f client primary primaryds secondary secondaryds tertiary tertiaryds 2>/dev/null || true
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

step "Set up primary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=primaryds.example.com \
    --network=example \
    --network-alias=primaryds.example.com \
    --password=Secret.123 \
    primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primary.example.com \
    --network=example \
    --network-alias=primary.example.com \
    primary

docker exec primary dnf install -y xmlstarlet
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp.cfg \
    -s OCSP \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CRL database in primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create DS backend
docker exec primaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryds.example.com:3389 \
    backend create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --be-name=crl

# add base entry
docker exec -i primaryds ldapadd \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: dc=crl,dc=pki,dc=example,dc=com
objectClass: domain
dc: crl
aci: (targetattr!="userPassword || aci")
 (version 3.0; acl "Enable anonymous access"; allow (read, search, compare) userdn="ldap:///anyone";)
EOF

# verify anonymous access
docker exec -i primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CRL database in primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove default OCSP publishing in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# remove default OCSP publisher
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.enableClientAuth
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.host
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.nickName
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.path
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.pluginName
docker exec primary pki-server ca-config-unset ca.publish.publisher.instance.OCSPPublisher-primary-example-com-8443.port

# remove default OCSP publishing rule
docker exec primary pki-server ca-config-unset ca.publish.rule.instance.ocsprule-primary-example-com-8443.enable
docker exec primary pki-server ca-config-unset ca.publish.rule.instance.ocsprule-primary-example-com-8443.mapper
docker exec primary pki-server ca-config-unset ca.publish.rule.instance.ocsprule-primary-example-com-8443.pluginName
docker exec primary pki-server ca-config-unset ca.publish.rule.instance.ocsprule-primary-example-com-8443.publisher
docker exec primary pki-server ca-config-unset ca.publish.rule.instance.ocsprule-primary-example-com-8443.type
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove default OCSP publishing in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP connection
docker exec primary pki-server ca-config-set ca.publish.ldappublish.enable true
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.authtype BasicAuth
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt internaldb
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.host primaryds.example.com
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.port 3389
docker exec primary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.secureConn false

# configure LDAP-based CA cert publisher
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr "cACertificate;binary"
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass pkiCA
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.pluginName LdapCaCertPublisher

# configure CA cert mapper
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.createCAEntry true
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.pluginName LdapCaSimpleMap

# configure CA cert publishing rule
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.enable true
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.mapper LdapCaCertMap
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.pluginName Rule
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.predicate ""
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.publisher LdapCaCertPublisher
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.type cacert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CRL publishing in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP-based CRL publisher
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlAttr "certificateRevocationList;binary"
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlObjectClass pkiCA
docker exec primary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.pluginName LdapCrlPublisher

# configure CRL mapper
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.createCAEntry true
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec primary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.pluginName LdapCaSimpleMap

# configure CRL publishing rule
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.enable true
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.mapper LdapCrlMap
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.pluginName Rule
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.predicate ""
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.publisher LdapCrlPublisher
docker exec primary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.type crl

# enable publishing
docker exec primary pki-server ca-config-set ca.publish.enable true

# set buffer size to 0 so that revocation will take effect immediately
docker exec primary pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec primary pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CRL publishing in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure revocation info store in primary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP store
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.numConns 1
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.host0 primaryds.example.com
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.port0 3389
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.baseDN0 "dc=crl,dc=pki,dc=example,dc=com"
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.byName true
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.caCertAttr "cACertificate;binary"
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.crlAttr "certificateRevocationList;binary"
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.includeNextUpdate false
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.notFoundAsGood true
docker exec primary pki-server ocsp-config-set ocsp.store.ldapStore.refreshInSec0 10

# enable LDAP store
docker exec primary pki-server ocsp-config-set ocsp.storeId ldapStore
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure revocation info store in primary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure primary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# disable access log buffer
docker exec primary xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec primary pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure primary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec primary pki-server ocsp-clone-prepare \
    --pkcs12-file $SHARED/ocsp-certs.p12 \
    --pkcs12-password Secret.123

docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=secondaryds.example.com \
    --network=example \
    --network-alias=secondaryds.example.com \
    --password=Secret.123 \
    secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondary.example.com \
    --network=example \
    --network-alias=secondary.example.com \
    secondary

docker exec secondary dnf install -y xmlstarlet
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-clone.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ocsp-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CRL database in secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create DS backend
docker exec secondaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryds.example.com:3389 \
    backend create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --be-name=crl

# add base entry
docker exec -i secondaryds ldapadd \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: dc=crl,dc=pki,dc=example,dc=com
objectClass: domain
dc: crl
aci: (targetattr!="userPassword || aci")
 (version 3.0; acl "Enable anonymous access"; allow (read, search, compare) userdn="ldap:///anyone";)
EOF

# verify anonymous access
docker exec -i secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL

# enable replication in primary DS
docker exec primaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryds.example.com:3389 \
    replication enable \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --role=supplier \
    --replica-id=1 \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123

# enable replication in secondary DS
docker exec secondaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryds.example.com:3389 \
    replication enable \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --role=supplier \
    --replica-id=2 \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123

# create replication agreement in primary DS
docker exec primaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --host=secondaryds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    primaryds-to-secondaryds

# create replication agreement in secondary DS
docker exec secondaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --host=primaryds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    secondaryds-to-primaryds

# start replication initialization
docker exec primaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryds.example.com:3389 \
    repl-agmt init \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    primaryds-to-secondaryds

# wait for initialization to complete
while true; do
    sleep 1

    docker exec primaryds dsconf \
        -D "cn=Directory Manager" \
        -w Secret.123 \
        ldap://primaryds.example.com:3389 \
        repl-agmt init-status \
        --suffix=dc=crl,dc=pki,dc=example,dc=com \
        primaryds-to-secondaryds \
        | tee output

    MSG=$(cat output)
    if [ "$MSG" = "Agreement successfully initialized." ]; then
        break
    fi
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CRL database in secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there's no default OCSP publishing to remove

# configure LDAP connection
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.enable true
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.authtype BasicAuth
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt internaldb
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.host secondaryds.example.com
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.port 3389
docker exec secondary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.secureConn false

# configure LDAP-based CA cert publisher
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr "cACertificate;binary"
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass pkiCA
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.pluginName LdapCaCertPublisher

# configure CA cert mapper
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.createCAEntry true
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.pluginName LdapCaSimpleMap

# configure CA cert publishing rule
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.enable true
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.mapper LdapCaCertMap
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.pluginName Rule
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.predicate ""
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.publisher LdapCaCertPublisher
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.type cacert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP-based CRL publisher
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlAttr "certificateRevocationList;binary"
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlObjectClass pkiCA
docker exec secondary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.pluginName LdapCrlPublisher

# configure CRL mapper
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.createCAEntry true
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec secondary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.pluginName LdapCaSimpleMap

# configure CRL publishing rule
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.enable true
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.mapper LdapCrlMap
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.pluginName Rule
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.predicate ""
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.publisher LdapCrlPublisher
docker exec secondary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.type crl

# enable publishing
docker exec secondary pki-server ca-config-set ca.publish.enable true

# set buffer size to 0 so that revocation will take effect immediately
docker exec secondary pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec secondary pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure revocation info store in secondary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP store
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.numConns 1
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.host0 secondaryds.example.com
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.port0 3389
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.baseDN0 "dc=crl,dc=pki,dc=example,dc=com"
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.byName true
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.caCertAttr "cACertificate;binary"
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.crlAttr "certificateRevocationList;binary"
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.includeNextUpdate false
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.notFoundAsGood true
docker exec secondary pki-server ocsp-config-set ocsp.store.ldapStore.refreshInSec0 10

# enable LDAP store
docker exec secondary pki-server ocsp-config-set ocsp.storeId ldapStore
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure revocation info store in secondary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure secondary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# disable access log buffer
docker exec secondary xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec secondary pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure secondary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CS.cfg"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp primary:/etc/pki/pki-tomcat/ca/CS.cfg CS.cfg.primary.CA
docker cp secondary:/etc/pki/pki-tomcat/ca/CS.cfg CS.cfg.secondary.CA

diff CS.cfg.primary.CA CS.cfg.secondary.CA || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CS.cfg (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP CS.cfg"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp primary:/etc/pki/pki-tomcat/ocsp/CS.cfg CS.cfg.primary.OCSP
docker cp secondary:/etc/pki/pki-tomcat/ocsp/CS.cfg CS.cfg.secondary.OCSP

diff CS.cfg.primary.OCSP CS.cfg.secondary.OCSP || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP CS.cfg (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up tertiary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tertiaryds.example.com \
    --network=example \
    --network-alias=tertiaryds.example.com \
    --password=Secret.123 \
    tertiaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up tertiary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=tertiary.example.com \
    --network=example \
    --network-alias=tertiary.example.com \
    tertiary

docker exec tertiary dnf install -y xmlstarlet
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone-of-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://tertiaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-clone-of-clone.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ocsp-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://tertiaryds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CRL database in tertiary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create DS backend
docker exec tertiaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://tertiaryds.example.com:3389 \
    backend create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --be-name=crl

# add base entry
docker exec -i tertiaryds ldapadd \
    -H ldap://tertiaryds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: dc=crl,dc=pki,dc=example,dc=com
objectClass: domain
dc: crl
aci: (targetattr!="userPassword || aci")
 (version 3.0; acl "Enable anonymous access"; allow (read, search, compare) userdn="ldap:///anyone";)
EOF

# verify anonymous access
docker exec -i tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL

# enable replication in tertiary DS
docker exec tertiaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://tertiaryds.example.com:3389 \
    replication enable \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --role=supplier \
    --replica-id=3 \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123

# create replication agreement in secondary DS
docker exec secondaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --host=tertiaryds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    secondaryds-to-tertiaryds

# create replication agreement in tertiary DS
docker exec tertiaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://tertiaryds.example.com:3389 \
    repl-agmt create \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    --host=secondaryds.example.com \
    --port=3389 \
    --conn-protocol=LDAP \
    --bind-dn="cn=Replication Manager,cn=config" \
    --bind-passwd=Secret.123 \
    --bind-method=SIMPLE \
    tertiaryds-to-secondaryds

# start replication initialization
docker exec secondaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://secondaryds.example.com:3389 \
    repl-agmt init \
    --suffix=dc=crl,dc=pki,dc=example,dc=com \
    secondaryds-to-tertiaryds

# wait for initialization to complete
while true; do
    sleep 1

    docker exec secondaryds dsconf \
        -D "cn=Directory Manager" \
        -w Secret.123 \
        ldap://secondaryds.example.com:3389 \
        repl-agmt init-status \
        --suffix=dc=crl,dc=pki,dc=example,dc=com \
        secondaryds-to-tertiaryds \
        | tee output

    MSG=$(cat output)
    if [ "$MSG" = "Agreement successfully initialized." ]; then
        break
    fi
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CRL database in tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there's no default OCSP publishing to remove

# configure LDAP connection
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.enable true
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.authtype BasicAuth
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt internaldb
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.host tertiaryds.example.com
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.port 3389
docker exec tertiary pki-server ca-config-set ca.publish.ldappublish.ldap.ldapconn.secureConn false

# configure LDAP-based CA cert publisher
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr "cACertificate;binary"
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass pkiCA
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCaCertPublisher.pluginName LdapCaCertPublisher

# configure CA cert mapper
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.createCAEntry true
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCaCertMap.pluginName LdapCaSimpleMap

# configure CA cert publishing rule
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.enable true
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.mapper LdapCaCertMap
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.pluginName Rule
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.predicate ""
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.publisher LdapCaCertPublisher
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCaCertRule.type cacert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CA cert publishing in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP-based CRL publisher
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlAttr "certificateRevocationList;binary"
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.crlObjectClass pkiCA
docker exec tertiary pki-server ca-config-set ca.publish.publisher.instance.LdapCrlPublisher.pluginName LdapCrlPublisher

# configure CRL mapper
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.createCAEntry true
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.dnPattern "cn=\$subj.cn,dc=crl,dc=pki,dc=example,dc=com"
docker exec tertiary pki-server ca-config-set ca.publish.mapper.instance.LdapCrlMap.pluginName LdapCaSimpleMap

# configure CRL publishing rule
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.enable true
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.mapper LdapCrlMap
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.pluginName Rule
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.predicate ""
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.publisher LdapCrlPublisher
docker exec tertiary pki-server ca-config-set ca.publish.rule.instance.LdapCrlRule.type crl

# enable publishing
docker exec tertiary pki-server ca-config-set ca.publish.enable true

# set buffer size to 0 so that revocation will take effect immediately
docker exec tertiary pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec tertiary pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CA cert publishing in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure revocation info store in tertiary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure LDAP store
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.numConns 1
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.host0 tertiaryds.example.com
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.port0 3389
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.baseDN0 "dc=crl,dc=pki,dc=example,dc=com"
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.byName true
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.caCertAttr "cACertificate;binary"
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.crlAttr "certificateRevocationList;binary"
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.includeNextUpdate false
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.notFoundAsGood true
docker exec tertiary pki-server ocsp-config-set ocsp.store.ldapStore.refreshInSec0 10

# enable LDAP store
docker exec tertiary pki-server ocsp-config-set ocsp.storeId ldapStore
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure revocation info store in tertiary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure tertiary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# disable access log buffer
docker exec tertiary xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec tertiary pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure tertiary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CS.cfg"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp tertiary:/etc/pki/pki-tomcat/ca/CS.cfg CS.cfg.tertiary.CA

diff CS.cfg.secondary.CA CS.cfg.tertiary.CA || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CS.cfg (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP CS.cfg"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp tertiary:/etc/pki/pki-tomcat/ocsp/CS.cfg CS.cfg.tertiary.OCSP

diff CS.cfg.secondary.OCSP CS.cfg.tertiary.OCSP || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP CS.cfg (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in primary container"
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
    docker exec primary pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in secondary container"
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
    docker exec secondary pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in tertiary container"
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
    docker exec tertiary pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in tertiary container (rc=$_rc)" >&2
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

step "Install admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin

docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin

docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ocsp-user-show \
    ocspadmin

docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ocsp-user-show \
    ocspadmin

docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ocsp-user-show \
    ocspadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "UID=testuser" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser.csr

docker exec client pki \
    -U https://primary.example.com:8443 \
    ca-cert-request-submit \
    --profile caUserCert \
    --csr-file testuser.csr \
    | tee output

REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" output)

docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-cert-request-approve \
    --force \
    $REQUEST_ID \
    | tee output

CERT_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" output)
echo "$CERT_ID" > cert.id

# wait for CRL update
sleep 10
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

# there should be no CRL attributes
sed -n "/^certificateRevocationList;binary:/p" output > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

# there should be no CRL attributes
sed -n "/^certificateRevocationList;binary:/p" output > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in tertiary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    "(objectClass=pkiCA)" \
    -t \
    | tee output

# there should be no CRL attributes
sed -n "/^certificateRevocationList;binary:/p" output > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert status in primary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://primary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be unknown
cat > expected << EOF
  Status: Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert status in primary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert status in secondary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://secondary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be unknown
cat > expected << EOF
  Status: Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert status in secondary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial cert status in tertiary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://tertiary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be unknown
cat > expected << EOF
  Status: Unknown
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial cert status in tertiary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke cert in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-cert-hold \
    --force \
    $CERT_ID

# wait for CRL update
sleep 10
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke cert in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec primary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec secondary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in tertiary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec tertiary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert in primary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://primary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be revoked
cat > expected << EOF
  Status: Revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert in primary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert in secondary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://secondary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be revoked
cat > expected << EOF
  Status: Revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert in secondary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert in tertiary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://tertiary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be revoked
cat > expected << EOF
  Status: Revoked
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert in tertiary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unrevoke cert in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-cert-release-hold \
    --force \
    $CERT_ID

# wait for CRL update
sleep 10
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke cert in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec primary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec secondary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL in tertiary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -x \
    -b "dc=crl,dc=pki,dc=example,dc=com" \
    -LLL \
    -o ldif_wrap=no \
    -t \
    "(objectClass=pkiCA)" \
    | tee output

FILENAME=$(sed -n 's/certificateRevocationList;binary:< file:\/\/\(.*\)$/\1/p' output)
echo "FILENAME: $FILENAME"

docker exec tertiary openssl crl \
    -in "$FILENAME" \
    -inform DER \
    -text \
    -noout \
    | tee output

# TODO: validate CRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL in tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert in primary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://primary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be good
cat > expected << EOF
  Status: Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert in primary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert in secondary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://secondary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be good
cat > expected << EOF
  Status: Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert in secondary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert in tertiary OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U http://tertiary.example.com:8080 \
    ocsp-cert-verify \
    --ca-cert ca_signing \
    $CERT_ID \
    | tee output

sed -n "/^\s*Status:/p" output > actual

# cert status should be good
cat > expected << EOF
  Status: Good
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert in tertiary OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP from tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP from tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP from primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for primary PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ls -l
docker exec primary find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for primary PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for secondary PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ls -l
docker exec secondary find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for secondary PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tertiary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tertiary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tertiaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for tertiary PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary ls -l
docker exec tertiary find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for tertiary PKI core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tertiary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tertiary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tertiary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tertiary OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ocsp-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-clone-test PASSED ===="
