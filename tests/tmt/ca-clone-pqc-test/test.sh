#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-pqc-test.yml
# Step names match the GHA workflow.
set -euo pipefail

REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
BIN="$REPO_ROOT/tests/bin"

export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"
# GHA persists env vars via $GITHUB_ENV; emulate with a temp file + source.
export GITHUB_ENV="${TMPDIR:-/tmp}/gha-env-$$"
touch "$GITHUB_ENV"
source_gha_env() { set -a; source "$GITHUB_ENV" 2>/dev/null || true; set +a; }
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

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec client sed -n 's/^VERSION_ID=//p' /etc/os-release)
echo "FEDORA_VERSION=$FEDORA_VERSION" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Fedora version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Enable ML-DSA in default crypto-policies for client"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec client sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies for client (rc=$_rc)" >&2
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

step "Enable ML-DSA in default crypto-policies for primary"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec primary sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies for primary (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
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

step "Check primary CA certificates ML-DSA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 > password.txt
# inspect cert with certutil
docker exec primary certutil -d /etc/pki/pki-tomcat/alias/ -K -f ${SHARED}/password.txt  | sed "/certutil: Checkin/d" | tee output

# all certificates should be "mldsa"
echo "mldsa" > expected
sed -E "s/^<\s?[0-9]+>\s(\w+)\b.*/\1/" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA certificates ML-DSA (rc=$_rc)" >&2
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

# inspect cert with certutil
docker exec client certutil -L -d /root/.dogtag/nssdb -n caadmin | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec primary openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
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

step "Enable ML-DSA in default crypto-policies for secondary"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec secondary sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies for secondary (rc=$_rc)" >&2
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
    -f /usr/share/pki/server/examples/installation/ca-clone-pqc.cfg \
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

step "Check secondary CA certificates ML-DSA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 > password.txt
# inspect cert with certutil
docker exec secondary certutil -d /etc/pki/pki-tomcat/alias/ -K -f ${SHARED}/password.txt  | sed "/certutil: Checkin/d" | tee output

# all certificates should be "mldsa"
echo "mldsa" > expected
sed -E "s/^<\s?[0-9]+>\s(\w+)\b.*/\1/" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA certificates ML-DSA (rc=$_rc)" >&2
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

step "Enable ML-DSA in default crypto-policies for tertiary"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies for tertiary (rc=$_rc)" >&2
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
    -f /usr/share/pki/server/examples/installation/ca-clone-pqc.cfg \
    -s CA \
    -D pki_security_domain_hostname=secondary.example.com \
    -D pki_clone_uri=https://secondary.example.com:8443 \
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

step "Check tertiary CA certificates ML-DSA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 > password.txt
# inspect cert with certutil
docker exec tertiary certutil -d /etc/pki/pki-tomcat/alias/ -K -f ${SHARED}/password.txt  | sed "/certutil: Checkin/d" | tee output

# all certificates should be "mldsa"
echo "mldsa" > expected
sed -E "s/^<\s?[0-9]+>\s(\w+)\b.*/\1/" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tertiary CA certificates ML-DSA (rc=$_rc)" >&2
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
    echo "==== ca-clone-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-pqc-test PASSED ===="
