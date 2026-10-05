#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-test.yml
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

step "Check schema in primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
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
    | grep "\-oid" \
    | sort \
    | tee primaryds.schema
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check schema in primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check initial replica range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-config.sh primary | tee output

# primary range should be 1-100 initially
cat > expected << EOF
dbs.beginReplicaNumber=1
dbs.endReplicaNumber=100
dbs.replicaCloneTransferNumber=5
dbs.replicaIncrement=100
dbs.replicaLowWaterMark=20
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial replica range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check initial CA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-objects.sh primaryds | tee output

# there should be no range allocations
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check initial CA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-next-range.sh primaryds | tee output

# next range should start from 1000
# see ou=replica in base/ca/database/ds/create.ldif
cat > expected << EOF
nextRange: 1000
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server status | tee output

# primary CA should be a domain manager
echo "True" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary CA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin cert for primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec client pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED

docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123

docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin cert for primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SD hosts in primary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    securitydomain-host-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SD hosts in primary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check users in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check users in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    ca-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in primary CA (rc=$_rc)" >&2
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

step "Install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA before cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary

docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server status | tee output

# secondary CA should be a domain manager
echo "True" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary CA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check schema in secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
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
    echo "FAIL: Check schema in secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication manager on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=Replication Manager masterAgreement1-secondary.example.com-pki-tomcat,ou=csusers,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication manager on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication manager on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=Replication Manager cloneAgreement1-secondary.example.com-pki-tomcat,ou=csusers,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication manager on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica object on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | tee output

# primary DS should have replica ID 96
echo "96" > expected
sed -n 's/^nsDS5ReplicaId:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica object on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica object on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | tee output

# secondary DS should have replica ID 97
echo "97" > expected
sed -n 's/^nsDS5ReplicaId:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica object on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replication agreement on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=masterAgreement1-secondary.example.com-pki-tomcat,cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replication agreement on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replication agreement on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=cloneAgreement1-secondary.example.com-pki-tomcat,cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replication agreement on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CS.cfg in primary CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA after cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after

docker exec primary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - remove params that cannot be compared
# - set dbs.enableSerialManagement to true (automatically enabled when cloned)
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e 's/^\(dbs.enableSerialManagement\)=.*$/\1=true/' \
    CS.cfg.primary \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.primary.after \
    | sort > actual

diff expected actual
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

docker exec secondary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - remove params that cannot be compared
# - replace primary.example.com with secondary.example.com
# - replace primaryds.example.com with secondaryds.example.com
# - set ca.crl.MasterCRL.enableCRLCache to false (automatically disabled in the clone)
# - set ca.crl.MasterCRL.enableCRLUpdates to false (automatically disabled in the clone)
# - add params for the clone
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
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
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
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

step "Check replica range config in primary CA after cloning"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-config.sh primary | tee output

# 5 numbers were transfered to secondary range
# so now primary range should be 1-95
cat > expected << EOF
dbs.beginReplicaNumber=1
dbs.endReplicaNumber=95
dbs.replicaCloneTransferNumber=5
dbs.replicaIncrement=100
dbs.replicaLowWaterMark=20
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica range config in primary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-config.sh secondary | tee output

# secondary range should be 96-100 initially
# first two numbers were assigned to primary DS and secondary DS
# so now secondary range should be 98-100
cat > expected << EOF
dbs.beginReplicaNumber=98
dbs.endReplicaNumber=100
dbs.replicaCloneTransferNumber=5
dbs.replicaIncrement=100
dbs.replicaLowWaterMark=20
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-objects.sh primaryds | tee output

# there should be no range allocations
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-next-range.sh primaryds | tee output

# next range should start from 1000
cat > expected << EOF
nextRange: 1000
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check admin cert for secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin cert for secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SD hosts in secondary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    securitydomain-host-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SD hosts in secondary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check users in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check users in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    ca-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in secondary CA (rc=$_rc)" >&2
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
docker exec secondary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

# export CA signing CSR
docker exec secondary pki-server cert-export ca_signing \
    --csr-file ${SHARED}/ca_signing.csr

# export CA OCSP signing CSR
docker exec secondary pki-server cert-export ca_ocsp_signing \
    --csr-file ${SHARED}/ca_ocsp_signing.csr

# export subsystem CSR
docker exec secondary pki-server cert-export subsystem \
    --csr-file ${SHARED}/subsystem.csr

docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone-of-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_ca_signing_csr_path=${SHARED}/ca_signing.csr \
    -D pki_ocsp_signing_csr_path=${SHARED}/ca_ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://tertiaryds.example.com:3389 \
    -v

docker exec tertiary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check schema in tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses attributeTypes \
    | grep "\-oid" | sort | tee tertiaryds.schema

diff secondaryds.schema tertiaryds.schema
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check schema in tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication manager on tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=Replication Manager cloneAgreement1-tertiary.example.com-pki-tomcat,ou=csusers,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication manager on tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica object on tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | tee output

# tertiary DS should have replica ID 1095
echo "1095" > expected
sed -n 's/^nsDS5ReplicaId:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica object on tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replication agreement on tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=cloneAgreement1-tertiary.example.com-pki-tomcat,cn=replica,cn=dc\3Dca\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replication agreement on tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CS.cfg in secondary CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary CA after cloning
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary.after

docker exec secondary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.secondary \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.secondary.after \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in secondary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from tertiary CA
docker cp tertiary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.tertiary

docker exec tertiary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - remove params that cannot be compared
# - replace secondary.example.com with tertiary.example.com
# - replace secondaryds.example.com with tertiaryds.example.com
# - set master.ca.agent.host to secondary.example.com
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    -e 's/secondary.example.com/tertiary.example.com/' \
    -e 's/secondaryds.example.com/tertiaryds.example.com/' \
    -e 's/^\(master.ca.agent.host\)=.*$/\1=secondary.example.com/' \
    CS.cfg.secondary.after \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    CS.cfg.tertiary \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check replica range config in secondary CA after cloning"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-config.sh secondary | tee output

# secondary range should remain 98-100
# next secondary range should be 1000-1099 initially
# 5 numbers were transferred to tertiary range
# so now next secondary range should be 1000-1094
cat > expected << EOF
dbs.beginReplicaNumber=98
dbs.endReplicaNumber=100
dbs.nextBeginReplicaNumber=1000
dbs.nextEndReplicaNumber=1094
dbs.replicaCloneTransferNumber=5
dbs.replicaIncrement=100
dbs.replicaLowWaterMark=20
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica range config in secondary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in tertiary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-config.sh tertiary | tee output

# tertiary range should be 1095-1099 initially
# first number is assigned to tertiary DS
# so now tertiary range should be 1096-1099
cat > expected << EOF
dbs.beginReplicaNumber=1096
dbs.endReplicaNumber=1099
dbs.replicaCloneTransferNumber=5
dbs.replicaIncrement=100
dbs.replicaLowWaterMark=20
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica range config in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-range-objects.sh primaryds | tee output

# range 1000-1099 should be allocated to secondary CA
cat > expected << EOF
SecurePort: 8443
beginRange: 1000
endRange: 1099
host: secondary.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-replica-next-range.sh primaryds | tee output

# next range should start from 1100
cat > expected << EOF
nextRange: 1100
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check admin cert for tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin cert for tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SD hosts in tertiary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    securitydomain-host-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SD hosts in tertiary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check users in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check users in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    ca-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in tertiary CA (rc=$_rc)" >&2
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert in primary CA (rc=$_rc)" >&2
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke cert in primary CA (rc=$_rc)" >&2
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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

step "Unrevoke cert in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)

docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-cert-release-hold \
    --force \
    $CERT_ID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke cert in tertiary CA (rc=$_rc)" >&2
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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
    --path /ca/ocsp \
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

step "Remove CA from tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tertiary.example.com:8443 \
    -n caadmin \
    ca-user-find

docker exec client pki \
    -U https://tertiary.example.com:8443 \
    securitydomain-host-find

docker exec tertiary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondary.example.com:8443 \
    -n caadmin \
    ca-user-find

docker exec client pki \
    -U https://secondary.example.com:8443 \
    securitydomain-host-find

docker exec secondary pkidestroy \
    -s CA \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove CA from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primary.example.com:8443 \
    -n caadmin \
    ca-user-find

docker exec client pki \
    -U https://primary.example.com:8443 \
    securitydomain-host-find

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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-test PASSED ===="
