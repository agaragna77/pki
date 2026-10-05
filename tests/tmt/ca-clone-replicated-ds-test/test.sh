#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-replicated-ds-test.yml
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
    docker rm -f primary primaryds secondary secondaryds 2>/dev/null || true
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -D pki_client_admin_cert_p12=$SHARED/caadmin.p12 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export ca_signing \
    --cert-file $SHARED/ca_signing.crt

docker exec primary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary pki pkcs12-import \
    --pkcs12 $SHARED/caadmin.p12 \
    --pkcs12-password Secret.123
docker exec primary pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA admin user (rc=$_rc)" >&2
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create secondary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server create
docker exec secondary pki-server nss-create --no-password
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create secondary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create secondary CA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create secondary CA subsystem (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export system certs and keys from primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export system certs and keys from primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import system certs and keys into secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    pkcs12-import \
    --pkcs12 $SHARED/ca-certs.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import system certs and keys into secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure connection to CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# store DS password
docker exec secondary pki-server password-set \
    --password Secret.123 \
    internaldb

# configure DS connection params
docker exec secondary pki-server ca-db-config-mod \
    --hostname secondaryds.example.com \
    --port 3389 \
    --secure false \
    --auth BasicAuth \
    --bindDN "cn=Directory Manager" \
    --bindPWPrompt internaldb \
    --database ca \
    --baseDN dc=ca,dc=pki,dc=example,dc=com \
    --multiSuffix false \
    --maxConns 15 \
    --minConns 3
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure connection to CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Preparing DS backend"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check backends in primary DS
docker exec primaryds dsconf \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    ldap://primaryds.example.com:3389 \
    backend suffix list

# create backend for CA in secondary DS
docker exec secondary pki-server ca-db-create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Preparing DS backend (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable replication on primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-db-repl-enable \
    --url ldap://primaryds.example.com:3389 \
    --bind-dn "cn=Directory Manager" \
    --bind-password Secret.123 \
    --replica-bind-dn "cn=Replication Manager,cn=config" \
    --replica-bind-password Secret.123 \
    --replica-id 1 \
    --suffix dc=ca,dc=pki,dc=example,dc=com \
    -v

# check replication manager
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=Replication Manager,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

# check replica object
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable replication on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable replication on secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-db-repl-enable \
    --url ldap://secondaryds.example.com:3389 \
    --bind-dn "cn=Directory Manager" \
    --bind-password Secret.123 \
    --replica-bind-dn "cn=Replication Manager,cn=config" \
    --replica-bind-password Secret.123 \
    --replica-id 2 \
    --suffix dc=ca,dc=pki,dc=example,dc=com \
    -v

# check replication manager
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=Replication Manager,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

# check replica object
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable replication on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create replication agreement on primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-db-repl-agmt-add \
    --url ldap://primaryds.example.com:3389 \
    --bind-dn "cn=Directory Manager" \
    --bind-password Secret.123 \
    --replica-url ldap://secondaryds.example.com:3389 \
    --replica-bind-dn "cn=Replication Manager,cn=config" \
    --replica-bind-password Secret.123 \
    --suffix dc=ca,dc=pki,dc=example,dc=com \
    -v \
    primaryds-to-secondaryds

# check replication agreement
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=primaryds-to-secondaryds,cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create replication agreement on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create replication agreement on secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-db-repl-agmt-add \
    --url ldap://secondaryds.example.com:3389 \
    --bind-dn "cn=Directory Manager" \
    --bind-password Secret.123 \
    --replica-url ldap://primaryds.example.com:3389 \
    --replica-bind-dn "cn=Replication Manager,cn=config" \
    --replica-bind-password Secret.123 \
    --suffix dc=ca,dc=pki,dc=example,dc=com \
    -v \
    secondaryds-to-primaryds

# check replication agreement
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=secondaryds-to-primaryds,cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create replication agreement on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initializing replication agreement"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-db-repl-agmt-init \
    --url ldap://primaryds.example.com:3389 \
    --bind-dn "cn=Directory Manager" \
    --bind-password Secret.123 \
    --suffix dc=ca,dc=pki,dc=example,dc=com \
    -v \
    primaryds-to-secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initializing replication agreement (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check schema in primary DS and secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses attributeTypes \
    | grep "\-oid" | sort | tee primaryds.schema

docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses attributeTypes \
    | grep "\-oid" | sort | tee secondaryds.schema

diff primaryds.schema secondaryds.schema
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check schema in primary DS and secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check entries in primary DS and secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get DNs from primary DS
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=ca,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL \
    dn \
    | sed -ne 's/^dn: \(.*\)$/\1/p' | sort | tee primaryds.dn

# get DNs from secondary DS
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "dc=ca,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL \
    dn \
    | sed -ne 's/^dn: \(.*\)$/\1/p' | sort > secondaryds.dn

diff primaryds.dn secondaryds.dn
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check entries in primary DS and secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-db-index-add -v
docker exec secondary pki-server ca-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA before cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -D pki_ds_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in primary CA and secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get system certs from primary CA (except sslserver)
docker exec primary pki-server cert-show ca_signing > system-certs.primary
echo >> system-certs.primary
docker exec primary pki-server cert-show ca_ocsp_signing >> system-certs.primary
echo >> system-certs.primary
docker exec primary pki-server cert-show ca_audit_signing >> system-certs.primary
echo >> system-certs.primary
docker exec primary pki-server cert-show subsystem >> system-certs.primary

# get system certs from secondary CA (except sslserver)
docker exec secondary pki-server cert-show ca_signing > system-certs.secondary
echo >> system-certs.secondary
docker exec secondary pki-server cert-show ca_ocsp_signing >> system-certs.secondary
echo >> system-certs.secondary
docker exec secondary pki-server cert-show ca_audit_signing >> system-certs.secondary
echo >> system-certs.secondary
docker exec secondary pki-server cert-show subsystem >> system-certs.secondary

cat system-certs.primary
diff system-certs.primary system-certs.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in primary CA and secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in primary CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA after cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after

diff CS.cfg.primary CS.cfg.primary.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in primary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary CA
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary

# normalize expected result:
# - remove params that cannot be compared
# - replace primary.example.com with secondary.example.com
# - replace primaryds.example.com with secondaryds.example.com
# - set ca.crl.MasterCRL.enableCRLCache to false (automatically disabled in the clone)
# - set ca.crl.MasterCRL.enableCRLUpdates to false (automatically disabled in the clone)
# - add params for the clone
sed -e '/^installDate=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    -e 's/primary.example.com/secondary.example.com/' \
    -e 's/primaryds.example.com/secondaryds.example.com/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLCache\)=.*$/\1=false/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLUpdates\)=.*$/\1=false/' \
    -e '$ a ca.certStatusUpdateInterval=0' \
    -e '$ a ca.listenToCloneModifications=false' \
    -e '$ a master.ca.agent.host=primary.example.com' \
    -e '$ a master.ca.agent.port=8443' \
    CS.cfg.primary.after \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^installDate=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    CS.cfg.secondary \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec secondary pki pkcs12-import \
    --pkcs12 $SHARED/caadmin.p12 \
    --pkcs12-password Secret.123
docker exec secondary pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check users in primary CA and secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki -n caadmin ca-user-find | tee ca-users.primary
docker exec secondary pki -n caadmin ca-user-find > ca-users.secondary

diff ca-users.primary ca-users.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check users in primary CA and secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in primary CA and secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki ca-cert-find | tee ca-certs.primary
docker exec secondary pki ca-cert-find > ca-certs.secondary

diff ca-certs.primary ca-certs.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in primary CA and secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain in primary CA and secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki securitydomain-show | tee sd.primary
docker exec secondary pki securitydomain-show > sd.secondary

diff sd.primary sd.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain in primary CA and secondary CA (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-replicated-ds-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-replicated-ds-test PASSED ===="
