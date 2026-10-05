#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-shared-ds-test.yml
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
    docker rm -f primary secondary 2>/dev/null || true
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
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export certs and keys from primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file ${SHARED}/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec primary pki-server cert-export ca_signing \
    --cert-file ${SHARED}/ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export certs and keys from primary CA (rc=$_rc)" >&2
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
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_ds_url=ldap://ds.example.com:3389 \
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

# normalize expected result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
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

# normalize expected result:
# - remove params that cannot be compared
# - replace primary.example.com with secondary.example.com
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

step "Check users in primary CA and secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get users from primary CA
docker exec primary pki-server cert-export ca_signing \
    --cert-file ${SHARED}/ca_signing.crt

docker exec primary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec primary pki -n caadmin ca-user-find | tee ca-users.primary

# get users from secondary CA
docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    ${SHARED}/ca_admin_cert.p12
docker exec secondary pki pkcs12-import \
    --pkcs12 ${SHARED}/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
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

step "Remove secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki -n caadmin ca-user-find
docker exec secondary pki securitydomain-host-find
docker exec secondary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki -n caadmin ca-user-find
docker exec primary pki securitydomain-host-find
docker exec primary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-shared-ds-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-shared-ds-test PASSED ===="
