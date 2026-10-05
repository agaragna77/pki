#!/bin/bash
# Generated TMT port of .github/workflows/tps-container-test.yml
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
    docker rm -f ca cads client kra krads tks tksds tps tpsds 2>/dev/null || true
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
# Packages needed: podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v podman-docker >/dev/null 2>&1 || dnf install -y podman-docker 2>/dev/null || true
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

step "Create shared folders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir -p ca/certs
mkdir -p ca/conf
mkdir -p ca/logs
mkdir -p kra/certs
mkdir -p kra/conf
mkdir -p kra/logs
mkdir -p tks/certs
mkdir -p tks/conf
mkdir -p tks/logs
mkdir -p tps/certs
mkdir -p tps/conf
mkdir -p tps/logs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create shared folders (rc=$_rc)" >&2
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

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name ca \
    --hostname ca.example.com \
    --network example \
    --network-alias ca.example.com \
    -v $PWD/ca/certs:/certs \
    -v $PWD/ca/conf:/conf \
    -v $PWD/ca/logs:/logs \
    --detach \
    pki-ca

# wait for CA to start
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker cp ca:ca_signing.crt .

docker exec client pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec client pki \
    -U https://ca.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=cads.example.com \
    --network=example \
    --network-alias=cads.example.com \
    --password=Secret.123 \
    cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-db-config-mod \
    --secure false \
    --hostname cads.example.com \
    --port 3389
docker exec ca pki-server password-set \
    --password Secret.123 \
    internaldb

docker exec ca pki-server ca-db-init -v
docker exec ca pki-server ca-db-index-add -v
docker exec ca pki-server ca-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/ca_signing.crt \
    ca_signing

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/ca_signing.crt \
    --csr /conf/certs/ca_signing.csr \
    --profile /usr/share/pki/ca/conf/caCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA OCSP signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/ca_ocsp_signing.crt \
    ca_ocsp_signing

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/ca_ocsp_signing.crt \
    --csr /conf/certs/ca_ocsp_signing.csr \
    --profile /usr/share/pki/ca/conf/caOCSPCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA OCSP signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA subsystem cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/subsystem.crt \
    subsystem

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/subsystem.crt \
    --csr /conf/certs/subsystem.csr \
    --profile /usr/share/pki/ca/conf/rsaSubsystemCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA subsystem cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import SSL server cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export \
    --cert-file /conf/certs/sslserver.crt \
    sslserver

docker exec ca pki-server ca-cert-import \
    --cert /conf/certs/sslserver.crt \
    --csr /conf/certs/sslserver.csr \
    --profile /usr/share/pki/ca/conf/rsaServerCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec client pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/admin.csr

docker cp admin.csr ca:.

# issue cert
docker exec ca pki-server ca-cert-create \
    --csr admin.csr \
    --profile /usr/share/pki/ca/conf/rsaAdminCert.profile \
    --cert /tmp/admin.crt \
    --import-cert

docker cp ca:/tmp/admin.crt .

# import cert
docker exec client pki nss-cert-import \
    --cert $SHARED/admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --cert /tmp/admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add admin user into CA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-role-add admin "Administrators"
docker exec ca pki-server ca-user-role-add admin "Certificate Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add admin user into CA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=DRM Storage Certificate" \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --csr $SHARED/kra/certs/kra_storage.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/kra_storage.csr \
    --ext /usr/share/pki/server/certs/kra_storage.conf \
    --cert $SHARED/kra/certs/kra_storage.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/kra_storage.crt \
    kra_storage
docker exec client pki nss-cert-show kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=DRM Transport Certificate" \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    --csr $SHARED/kra/certs/kra_transport.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/kra_transport.csr \
    --ext /usr/share/pki/server/certs/kra_transport.conf \
    --cert $SHARED/kra/certs/kra_transport.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/kra_transport.crt \
    kra_transport
docker exec client pki nss-cert-show kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/kra/certs/subsystem.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/kra/certs/subsystem.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/subsystem.crt \
    kra_subsystem
docker exec client pki nss-cert-show kra_subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=kra.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/kra/certs/sslserver.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/kra/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/kra/certs/sslserver.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/kra/certs/sslserver.crt \
    kra_sslserver
docker exec client pki nss-cert-show kra_sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare KRA certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec client cp $SHARED/ca/conf/certs/ca_signing.crt $SHARED/kra/certs

docker exec client pki nss-cert-find

# export KRA system certs and keys
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123 \
    kra_storage \
    kra_transport \
    kra_subsystem \
    kra_sslserver

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "subsystem" \
    kra_subsystem

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "sslserver" \
    kra_sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/kra/certs/server.p12 \
    --password Secret.123

ls -la kra/certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare KRA certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name kra \
    --hostname kra.example.com \
    --network example \
    --network-alias kra.example.com \
    -v $PWD/kra/certs:/certs \
    -v $PWD/kra/conf:/conf \
    -v $PWD/kra/logs:/logs \
    --detach \
    pki-kra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for KRA container to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://kra.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for KRA container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=krads.example.com \
    --network=example \
    --network-alias=krads.example.com \
    --password=Secret.123 \
    krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-db-config-mod \
    --secure false \
    --hostname krads.example.com \
    --port 3389
docker exec kra pki-server password-set \
    --password Secret.123 \
    internaldb

docker exec kra pki-server kra-db-init -v
docker exec kra pki-server kra-db-index-add -v
docker exec kra pki-server kra-db-index-rebuild  -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp admin.crt kra:.

docker exec kra pki-server kra-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA admin user into KRA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-role-add admin "Administrators"
docker exec kra pki-server kra-user-role-add admin "Data Recovery Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA admin user into KRA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA subsystem user in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cp ca/conf/certs/subsystem.crt kra/conf/certs/ca_subsystem.crt
docker exec kra pki-server kra-user-add \
    --full-name CA \
    --type agentType \
    --cert /conf/certs/ca_subsystem.crt \
    CA
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA subsystem user in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to CA subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-role-add CA "Trusted Managers"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to CA subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp kra/certs/kra_transport.crt ca:.
docker exec ca pki-server ca-connector-add \
   --url https://kra.example.com:8443 \
   --nickname subsystem \
   --transport-cert kra_transport.crt \
   KRA
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create TKS subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/tks/certs/subsystem.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/tks/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/tks/certs/subsystem.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/tks/certs/subsystem.crt \
    tks_subsystem
docker exec client pki nss-cert-show tks_subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create TKS subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create TKS SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=tks.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/tks/certs/sslserver.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/tks/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/tks/certs/sslserver.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/tks/certs/sslserver.crt \
    tks_sslserver
docker exec client pki nss-cert-show tks_sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create TKS SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare TKS certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import CA signing cert
docker exec client cp $SHARED/ca/conf/certs/ca_signing.crt $SHARED/tks/certs

# export TKS system certs and keys
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/tks/certs/server.p12 \
    --password Secret.123 \
    tks_subsystem \
    tks_sslserver

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/tks/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "subsystem" \
    tks_subsystem

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/tks/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "sslserver" \
    tks_sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/tks/certs/server.p12 \
    --password Secret.123

ls -la tks/certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare TKS certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name tks \
    --hostname tks.example.com \
    --network example \
    --network-alias tks.example.com \
    -v $PWD/tks/certs:/certs \
    -v $PWD/tks/conf:/conf \
    -v $PWD/tks/logs:/logs \
    --detach \
    pki-tks
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for TKS container to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://tks.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for TKS container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tks.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TKS DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tksds.example.com \
    --network=example \
    --network-alias=tksds.example.com \
    --password=Secret.123 \
    tksds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TKS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-db-config-mod \
    --secure false \
    --hostname tksds.example.com \
    --port 3389
docker exec tks pki-server password-set \
    --password Secret.123 \
    internaldb

docker exec tks pki-server tks-db-init -v
docker exec tks pki-server tks-db-index-add -v
docker exec tks pki-server tks-db-index-rebuild  -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TKS admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp admin.crt tks:.

docker exec tks pki-server tks-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TKS admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TKS admin user into TKS groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-user-role-add admin "Administrators"
docker exec tks pki-server tks-user-role-add admin "Token Key Service Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TKS admin user into TKS groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import KRA transport cert into TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp kra/certs/kra_transport.crt tks:.

# import KRA transport cert
docker exec tks pki-server cert-import \
    --input kra_transport.crt \
    --nickname kra_transport

# configure TKS to use KRA transport cert
docker exec tks pki-server tks-config-set \
    tks.drm_transport_cert_nickname \
    kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import KRA transport cert into TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create shared secret in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-create \
    --key-type AES \
    --op-flags WRAP,UNWRAP,ENCRYPT,ENCRYPT \
    "TPS sharedSecret"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create shared secret in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS connector in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-connector-add \
   --url https://tps.example.com:8443 \
   --nickname "TPS sharedSecret" \
   --uid TPS \
   0
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS connector in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create TPS subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --csr $SHARED/tps/certs/subsystem.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/tps/certs/subsystem.csr \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    --cert $SHARED/tps/certs/subsystem.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/tps/certs/subsystem.crt \
    tps_subsystem
docker exec client pki nss-cert-show tps_subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create TPS subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create TPS SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki nss-cert-request \
    --subject "CN=tps.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/tps/certs/sslserver.csr
docker exec client pki \
    -d $SHARED/ca/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/tps/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/tps/certs/sslserver.crt
docker exec client pki nss-cert-import \
    --cert $SHARED/tps/certs/sslserver.crt \
    tps_sslserver
docker exec client pki nss-cert-show tps_sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create TPS SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Prepare TPS certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import CA signing cert
docker exec client cp $SHARED/ca/conf/certs/ca_signing.crt $SHARED/tps/certs

# export TPS system certs and keys
docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/tps/certs/server.p12 \
    --password Secret.123 \
    tps_subsystem \
    tps_sslserver

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/tps/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "subsystem" \
    tps_subsystem

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/tps/certs/server.p12 \
    --password Secret.123 \
    --friendly-name "sslserver" \
    tps_sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/tps/certs/server.p12 \
    --password Secret.123

ls -la tps/certs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Prepare TPS certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name tps \
    --hostname tps.example.com \
    --network example \
    --network-alias tps.example.com \
    -v $PWD/tps/certs:/certs \
    -v $PWD/tps/conf:/conf \
    -v $PWD/tps/logs:/logs \
    --detach \
    pki-tps
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for TPS container to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://tps.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for TPS container to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec tps sed -n 's/^VERSION_ID=//p' /etc/os-release)
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

step "Get Tomcat flavor"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TOMCAT_FLAVOR=$(docker exec tps test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
echo "TOMCAT_FLAVOR=$TOMCAT_FLAVOR" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Tomcat flavor (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Check TPS conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l tps/conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- runner Catalina
drwxrwx--- runner alias
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- runner password.conf
-rw-rw---- runner server.xml
-rw-rw---- runner serverCertNick.conf
-rw-rw---- runner tomcat.conf
drwxrwx--- runner tps
lrwxrwxrwx runner web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- runner Catalina
drwxrwx--- runner alias
-rw-rw---- runner catalina.policy
lrwxrwxrwx runner catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- runner certs
lrwxrwxrwx runner context.xml -> /etc/tomcat/context.xml
-rw-rw---- runner jss.conf
lrwxrwxrwx runner logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- runner password.conf
-rw-rw---- runner server.xml
-rw-rw---- runner serverCertNick.conf
-rw-rw---- runner tomcat.conf
drwxrwx--- runner tps
lrwxrwxrwx runner web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS conf/tps dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
ls -l tps/conf/tps \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
        -e '/^\S* *\S* *CS.cfg.bak /d' \
    | tee output

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- runner CS.cfg
drwxrwxrwx runner archives
-rw-rw---- runner phoneHome.xml
-rw-rw---- runner registry.cfg
EOF

cat > expected_new << EOF
-rw-rw---- runner CS.cfg
drwxrwxrwx runner archives
-rw-rw---- runner phoneHome.xml
-rw-rw---- runner registry.cfg
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS conf/tps dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
ls -l tps/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected << EOF
drwxrwx--- runner backup
-rw-rw---- runner localhost.$DATE.log
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner pki
drwxrwx--- runner tps
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
ls -l tps/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by runner group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- runner backup
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner tps
EOF

cat > expected_new << EOF
drwxrwx--- runner backup
-rw-rw-rw- runner localhost_access_log.$DATE.txt
drwxrwx--- runner tps
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tps.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tpsds.example.com \
    --network=example \
    --network-alias=tpsds.example.com \
    --password=Secret.123 \
    tpsds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-db-config-mod \
    --secure false \
    --hostname tpsds.example.com \
    --port 3389
docker exec tps pki-server password-set \
    --password Secret.123 \
    internaldb

docker exec tps pki-server tps-db-init -v
docker exec tps pki-server tps-db-index-add -v
docker exec tps pki-server tps-db-index-rebuild  -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp admin.crt tps:.

# allow admin user to access all profiles
docker exec tps pki-server tps-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    --tps-profiles "All Profiles" \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS admin user into TPS groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-user-role-add admin "Administrators"
docker exec tps pki-server tps-user-role-add admin "TPS Agents"
docker exec tps pki-server tps-user-role-add admin "TPS Operators"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS admin user into TPS groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS subsystem user in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp tps/certs/subsystem.crt ca:tps_subsystem.crt

docker exec ca pki-server ca-user-add \
    --full-name TPS \
    --type agentType \
    --cert tps_subsystem.crt \
    TPS

docker exec ca pki-server ca-user-role-add \
    TPS \
    "Certificate Manager Agents"

docker exec ca pki-server ca-user-role-add \
    TPS \
    "Subsystem Group"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS subsystem user in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA connector in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-connector-add \
    --type CA \
    --url https://ca.example.com:8443 \
    --nickname subsystem \
    ca1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA connector in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS subsystem user in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp tps/certs/subsystem.crt kra:tps_subsystem.crt

docker exec kra pki-server kra-user-add \
    --full-name TPS \
    --type agentType \
    --cert tps_subsystem.crt \
    TPS

docker exec kra pki-server kra-user-role-add \
    TPS \
    "Data Recovery Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS subsystem user in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA connector in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-connector-add \
   --type KRA \
   --url https://kra.example.com:8443 \
   --nickname subsystem \
   kra1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA connector in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TPS subsystem user in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp tps/certs/subsystem.crt tks:tps_subsystem.crt

docker exec tks pki-server tks-user-add \
    --full-name TPS \
    --type agentType \
    --cert tps_subsystem.crt \
    TPS

docker exec tks pki-server tks-user-role-add \
    TPS \
    "Token Key Service Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TPS subsystem user in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add TKS connector in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-connector-add \
   --type TKS \
   --url https://tks.example.com:8443 \
   --nickname subsystem \
   --keygen \
   tks1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add TKS connector in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import shared secret into TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export shared secret from TKS
docker exec tks pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-export \
    --wrapper-cert tps_subsystem.crt \
    --output shared-secret.json \
    "TPS sharedSecret"

docker cp tks:shared-secret.json .
docker cp shared-secret.json tps:.

# import shared secret into TPS
docker exec tps pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-import \
    --input shared-secret.json \
    --wrapper subsystem \
    "TPS sharedSecret"

# configure shared secret in TPS
docker exec tps pki-server tps-config-set \
    conn.tks1.tksSharedSymKeyName \
    "TPS sharedSecret"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import shared secret into TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up user auth database for TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure connection to auth database
docker exec tps pki-server tps-config-set \
    auths.instance.ldap1.ldap.ldapconn.secureConn \
    false
docker exec tps pki-server tps-config-set \
    auths.instance.ldap1.ldap.ldapconn.host \
    tpsds.example.com
docker exec tps pki-server tps-config-set \
    auths.instance.ldap1.ldap.ldapconn.port \
    3389
docker exec tps pki-server tps-config-set \
    auths.instance.ldap1.ldap.basedn \
    ou=people,dc=example,dc=com

# import base entry
docker exec tps ldapadd \
    -H ldap://tpsds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/tps/auth/ds/create.ldif

# import sample users
docker exec tps ldapadd \
    -H ldap://tpsds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -f /usr/share/pki/tps/auth/ds/example.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up user auth database for TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure TPS for testing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# allow TPS client to work
docker exec tps pki-server tps-config-set \
    channel.scp01.no.le.byte \
    true

# reset PIN_RESET after PIN reset
docker exec tps pki-server tps-config-set \
    tokendb.defaultPolicy \
    "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=YES"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure TPS for testing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart ca
sleep 10

docker network reload --all

# wait for CA to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin user after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n admin \
    ca-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart kra
sleep 10

docker network reload --all

# wait for KRA to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://kra.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin user after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin user after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart tks
sleep 10

docker network reload --all

# wait for TKS to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://tks.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS admin user after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tks.example.com:8443 \
    -n admin \
    tks-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS admin user after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS connector in TKS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-config-find | grep ^tps. | sort | tee output

cat > expected << EOF
tps.0.host=tps.example.com
tps.0.nickname=TPS sharedSecret
tps.0.port=8443
tps.0.userid=TPS
tps.list=0
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS connector in TKS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker restart tps
sleep 10

docker network reload --all

# wait for TPS to restart
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://tps.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS admin user after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS admin user after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in CA after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-show TPS
docker exec ca pki-server ca-user-role-find TPS
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in CA after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA connector in TPS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-config-find | grep ^tps.connector.ca1. | tee output

cat > expected << EOF
tps.connector.ca1.enable=true
tps.connector.ca1.host=ca.example.com
tps.connector.ca1.maxHttpConns=15
tps.connector.ca1.minHttpConns=1
tps.connector.ca1.nickName=subsystem
tps.connector.ca1.port=8443
tps.connector.ca1.timeout=30
tps.connector.ca1.uri.enrollment=/ca/ee/ca/profileSubmitSSLClient
tps.connector.ca1.uri.getcert=/ca/ee/ca/displayBySerial
tps.connector.ca1.uri.renewal=/ca/ee/ca/profileSubmitSSLClient
tps.connector.ca1.uri.revoke=/ca/ee/subsystem/ca/doRevoke
tps.connector.ca1.uri.unrevoke=/ca/ee/subsystem/ca/doUnrevoke
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA connector in TPS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in KRA after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-show TPS
docker exec kra pki-server kra-user-role-find TPS
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in KRA after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in TPS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-config-find | grep ^tps.connector.kra1. | tee output

cat > expected << EOF
tps.connector.kra1.enable=true
tps.connector.kra1.host=kra.example.com
tps.connector.kra1.maxHttpConns=15
tps.connector.kra1.minHttpConns=1
tps.connector.kra1.nickName=subsystem
tps.connector.kra1.port=8443
tps.connector.kra1.timeout=30
tps.connector.kra1.uri.GenerateKeyPair=/kra/agent/kra/GenerateKeyPair
tps.connector.kra1.uri.TokenKeyRecovery=/kra/agent/kra/TokenKeyRecovery
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in TPS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in TKS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-user-show TPS
docker exec tks pki-server tks-user-role-find TPS
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in TKS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS connector in TPS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-config-find | grep ^tps.connector.tks1. | tee output

cat > expected << EOF
tps.connector.tks1.enable=true
tps.connector.tks1.generateHostChallenge=true
tps.connector.tks1.host=tks.example.com
tps.connector.tks1.keySet=defKeySet
tps.connector.tks1.maxHttpConns=15
tps.connector.tks1.minHttpConns=1
tps.connector.tks1.nickName=subsystem
tps.connector.tks1.port=8443
tps.connector.tks1.serverKeygen=true
tps.connector.tks1.timeout=30
tps.connector.tks1.tksSharedSymKeyName=sharedSecret
tps.connector.tks1.uri.computeRandomData=/tks/agent/tks/computeRandomData
tps.connector.tks1.uri.computeSessionKey=/tks/agent/tks/computeSessionKey
tps.connector.tks1.uri.createKeySetData=/tks/agent/tks/createKeySetData
tps.connector.tks1.uri.encryptData=/tks/agent/tks/encryptData
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS connector in TPS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check shared secret in TPS after restart"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find

docker exec tps pki-server tps-config-find | grep ^conn. | tee output

cat > expected << EOF
conn.tks1.tksSharedSymKeyName=TPS sharedSecret
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check shared secret in TPS after restart (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
hexdump -v -n "10" -e '1/1 "%02x"' /dev/urandom > cuid
CUID=$(cat cuid)

# allow one-time PIN reset
docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-token-add \
    --policy "PIN_RESET=YES" \
    $CUID | tee output

sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual

# token should be unformatted
echo "UNFORMATTED" > expected
diff expected actual

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-cert-find \
    --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Format token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec client /usr/share/pki/tps/bin/pki-tps-format \
    --hostname=tps.example.com \
    --user=testuser \
    --password=Secret.123 \
    $CUID

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-token-show \
    $CUID \
    | tee output

sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual

# token should be formatted
echo "FORMATTED" > expected

diff expected actual

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-cert-find \
    --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Format token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec client /usr/share/pki/tps/bin/pki-tps-enroll \
    --hostname=tps.example.com \
    --user=testuser \
    --password=Secret.123 \
    $CUID

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-token-show \
    $CUID \
    | tee output

sed -n 's/\s*Status:\s\+\(\S\+\)\s*/\1/p' output > actual

# token should be active
echo "ACTIVE" > expected

diff expected actual

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-cert-find \
    --token $CUID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Reset PIN"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid)
docker exec client /usr/share/pki/tps/bin/pki-tps-pin-reset \
    --hostname=tps.example.com \
    --user=testuser \
    --password=Secret.123 \
    --new-password=Secret.456 \
    $CUID

# TODO: validate new PIN

docker exec client pki \
    -U https://tps.example.com:8443 \
    -n admin \
    tps-token-show \
    $CUID \
    | tee output

sed -n 's/\s*Policy:\s\+\(\S\+\)\s*/\1/p' output > actual

# PIN_RESET should become NO
echo "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=YES;RENEW_KEEP_OLD_ENC_CERTS=YES" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Reset PIN (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check user key in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CUID=$(cat cuid | tr [:lower:] [:upper:])
USER="testuser"

docker exec client pki \
    -U https://kra.example.com:8443 \
    -n admin \
    kra-key-find \
    --owner $CUID:$USER \
    | tee output

sed -n 's/\s*Owner:\s\+\(\S\+\)\s*/\1/p' output > actual

# user key should exist
echo "$CUID:$USER" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check user key in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec cads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ca 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec krads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs kra 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tksds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tksds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tks 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tpsds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tpsds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tps 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tps find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tps find /var/lib/pki/pki-tomcat/logs/tps -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check client container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== tps-container-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== tps-container-test PASSED ===="
