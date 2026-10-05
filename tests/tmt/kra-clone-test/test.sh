#!/bin/bash
# Generated TMT port of .github/workflows/kra-clone-test.yml
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
    docker rm -f primary primaryds secondary secondaryds tertiary tertiaryds 2>/dev/null || true
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

step "Install primary CA in primary PKI container"
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

docker exec primary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary CA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary KRA in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -v

docker exec primary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary KRA in primary PKI container (rc=$_rc)" >&2
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

step "Check initial replica range config in primary KRA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-config.sh primary | tee output

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
    echo "FAIL: Check initial replica range config in primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check initial KRA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-objects.sh primaryds | tee output

# there should be no range allocations
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial KRA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check initial KRA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-next-range.sh primaryds | tee output

# next range should start from 1000
# see ou=replica in base/kra/database/ds/create.ldif
cat > expected << EOF
nextRange: 1000
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial KRA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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
docker exec primary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -v

docker exec secondary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server kra-clone-prepare \
    --pkcs12-file $SHARED/kra-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-clone.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/kra-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -v

docker exec secondary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in secondary PKI container (rc=$_rc)" >&2
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

step "Check KRA replica object on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
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
    echo "FAIL: Check KRA replica object on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replica object on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
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
    echo "FAIL: Check KRA replica object on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replication agreement on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds ldapsearch \
    -H ldap://primaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=masterAgreement1-secondary.example.com-pki-tomcat,cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replication agreement on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replication agreement on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds ldapsearch \
    -H ldap://secondaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=cloneAgreement1-secondary.example.com-pki-tomcat,cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replication agreement on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in primary KRA after cloning"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-config.sh primary | tee output

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
    echo "FAIL: Check replica range config in primary KRA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in secondary KRA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-config.sh secondary | tee output

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
    echo "FAIL: Check replica range config in secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-objects.sh primaryds | tee output

# there should be no range allocations
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-next-range.sh primaryds | tee output

# next range should start from 1000
cat > expected << EOF
nextRange: 1000
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Verify KRA admin in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary cp /root/.dogtag/pki-tomcat/ca_admin_cert.p12 $SHARED/ca_admin_cert.p12

docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec secondary pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123

docker exec secondary pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA admin in secondary PKI container (rc=$_rc)" >&2
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
docker exec secondary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec secondary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone-of-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
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

step "Install KRA in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server kra-clone-prepare \
    --pkcs12-file $SHARED/kra-certs.p12 \
    --pkcs12-password Secret.123

docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-clone-of-clone.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/kra-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://tertiaryds.example.com:3389 \
    -v

docker exec tertiary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in tertiary PKI container (rc=$_rc)" >&2
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

step "Check KRA replica object on tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
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
    echo "FAIL: Check KRA replica object on tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replication agreement on tertiary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiaryds ldapsearch \
    -H ldap://tertiaryds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=cloneAgreement1-tertiary.example.com-pki-tomcat,cn=replica,cn=dc\3Dkra\2Cdc\3Dpki\2Cdc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replication agreement on tertiary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in secondary KRA after cloning"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-config.sh secondary | tee output

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
    echo "FAIL: Check replica range config in secondary KRA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica range config in tertiary KRA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-config.sh tertiary | tee output

# tertiary range should be 1095-1099 initially
# first number is assigned to the tertiary DS
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
    echo "FAIL: Check replica range config in tertiary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replica range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-range-objects.sh primaryds | tee output

# 1000-1099 should be allocated to secondary range
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
    echo "FAIL: Check KRA replica range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA replica next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/kra/bin/kra-replica-next-range.sh primaryds | tee output

# next range should start from 1100
cat > expected << EOF
nextRange: 1100
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA replica next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Verify KRA admin in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec tertiary pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123

docker exec tertiary pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA admin in tertiary PKI container (rc=$_rc)" >&2
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

step "Remove KRA from tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA from tertiary PKI container (rc=$_rc)" >&2
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

step "Remove KRA from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA from secondary PKI container (rc=$_rc)" >&2
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

step "Remove KRA from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA from primary PKI container (rc=$_rc)" >&2
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

step "Check PKI server systemd journal in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in primary container (rc=$_rc)" >&2
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

step "Check primary KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary KRA debug log (rc=$_rc)" >&2
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

step "Check PKI server systemd journal in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in secondary container (rc=$_rc)" >&2
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

step "Check secondary KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary KRA debug log (rc=$_rc)" >&2
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

step "Check PKI server systemd journal in tertiary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in tertiary container (rc=$_rc)" >&2
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

step "Check tertiary KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tertiary find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-clone-test PASSED ===="
