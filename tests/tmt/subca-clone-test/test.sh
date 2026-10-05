#!/bin/bash
# Generated TMT port of .github/workflows/subca-clone-test.yml
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
    docker rm -f primary root secondary 2>/dev/null || true
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

step "Set up root CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=root-ca.example.com \
    --network=example \
    --network-alias=root-ca.example.com \
    root-ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create root CA in NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root-ca pki nss-cert-request \
    --subject "CN=Root CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/root-ca_signing.csr
docker exec root-ca pki nss-cert-issue \
    --csr $SHARED/root-ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert $SHARED/root-ca_signing.crt

docker exec root-ca pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create root CA in NSS database (rc=$_rc)" >&2
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
    --hostname=primary-ds.example.com \
    --network=example \
    --network-alias=primary-ds.example.com \
    --password=Secret.123 \
    primary-ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary sub-CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primary-subca.example.com \
    --network=example \
    --network-alias=primary-subca.example.com \
    primary-subca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary sub-CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary sub-CA (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step1.cfg \
    -s CA \
    -D pki_ds_url=ldap://primary-ds.example.com:3389 \
    -D pki_ca_signing_csr_path=$SHARED/subca_signing.csr \
    -D pki_client_admin_cert_p12=$SHARED/caadmin.p12 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary sub-CA (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue primary sub-CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root-ca pki nss-cert-issue \
    --issuer root-ca_signing \
    --csr $SHARED/subca_signing.csr \
    --ext /usr/share/pki/server/certs/subca_signing.conf \
    --cert $SHARED/subca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue primary sub-CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary sub-CA (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step2.cfg \
    -s CA \
    -D pki_ds_url=ldap://primary-ds.example.com:3389 \
    -D pki_cert_chain_path=${SHARED}/root-ca_signing.crt \
    -D pki_ca_signing_csr_path=$SHARED/subca_signing.csr \
    -D pki_ca_signing_cert_path=$SHARED/subca_signing.crt \
    -D pki_client_admin_cert_p12=$SHARED/caadmin.p12 \
    -v

docker exec primary-subca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary sub-CA (step 2) (rc=$_rc)" >&2
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
    docker exec primary-subca pki-healthcheck --failures-only
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

step "Check primary sub-CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec primary-subca pki nss-cert-import \
    --cert $SHARED/subca_signing.crt \
    ca_signing

docker exec primary-subca pki pkcs12-import \
    --pkcs12 $SHARED/caadmin.p12 \
    --pkcs12-password Secret.123

docker exec primary-subca pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary sub-CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export primary sub-CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pki-server ca-clone-prepare \
    --pkcs12-file ${SHARED}/subca-certs.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export primary sub-CA certs (rc=$_rc)" >&2
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
    --hostname=secondary-ds.example.com \
    --network=example \
    --network-alias=secondary-ds.example.com \
    --password=Secret.123 \
    secondary-ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary sub-CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondary-subca.example.com \
    --network=example \
    --network-alias=secondary-subca.example.com \
    secondary-subca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary sub-CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install secondary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary sub-CA before cloning
docker cp primary-subca:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary

docker exec secondary-subca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/root-ca_signing.crt \
    -D pki_security_domain_hostname=primary-subca.example.com \
    -D pki_clone_pkcs12_path=${SHARED}/subca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_ds_url=ldap://secondary-ds.example.com:3389 \
    -D pki_clone_uri=https://primary-subca.example.com:8443 \
    -v

docker exec secondary-subca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install secondary sub-CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in primary sub-CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary sub-CA after cloning
docker cp primary-subca:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after

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
    echo "FAIL: Check CS.cfg in primary sub-CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in secondary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary sub-CA
docker cp secondary-subca:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary

# normalize expected result:
# - remove params that cannot be compared
# - replace primary-subca.example.com with secondary-subca.example.com
# - replace primary-ds.example.com with secondary-ds.example.com
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
    -e 's/primary-subca.example.com/secondary-subca.example.com/' \
    -e 's/primary-ds.example.com/secondary-ds.example.com/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLCache\)=.*$/\1=false/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLUpdates\)=.*$/\1=false/' \
    -e '$ a ca.certStatusUpdateInterval=0' \
    -e '$ a ca.listenToCloneModifications=false' \
    -e '$ a master.ca.agent.host=primary-subca.example.com' \
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
    echo "FAIL: Check CS.cfg in secondary sub-CA (rc=$_rc)" >&2
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
    docker exec secondary-subca pki-healthcheck --failures-only
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

step "Check secondary sub-CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary-subca pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec secondary-subca pki nss-cert-import \
    --cert $SHARED/subca_signing.crt \
    ca_signing

docker exec secondary-subca pki pkcs12-import \
    --pkcs12 $SHARED/caadmin.p12 \
    --pkcs12-password Secret.123

docker exec secondary-subca pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary sub-CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check users in primary sub-CA and secondary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pki -n caadmin ca-user-find | tee subca-users.primary
docker exec secondary-subca pki -n caadmin ca-user-find > subca-users.secondary

diff subca-users.primary subca-users.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check users in primary sub-CA and secondary sub-CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs in primary sub-CA and secondary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pki ca-cert-find | tee subca-certs.primary
docker exec secondary-subca pki ca-cert-find > subca-certs.secondary

diff subca-certs.primary subca-certs.secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs in primary sub-CA and secondary sub-CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove secondary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary-subca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary sub-CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary sub-CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for root CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec root-ca ls -l
docker exec root-ca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for root CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for primary sub-CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary-subca ls -l
docker exec primary-subca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for primary sub-CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for secondary sub-CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary-subca ls -l
docker exec secondary-subca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for secondary sub-CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== subca-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== subca-clone-test PASSED ===="
