#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-secure-ds-test.yml
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

step "Create DS signing cert in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki \
    nss-cert-request \
    --subject "CN=DS Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ds_signing.csr

docker exec primary pki \
    nss-cert-issue \
    --csr ds_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ds_signing.crt

docker exec primary pki nss-cert-import \
    --cert ds_signing.crt \
    --trust CT,C,C \
    Self-Signed-CA

docker exec primary pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create DS signing cert in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create DS server cert in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki \
    nss-cert-request \
    --subject "CN=primaryds.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr ds_server.csr

docker exec primary pki \
    nss-cert-issue \
    --issuer Self-Signed-CA \
    --csr ds_server.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert ds_server.crt

docker exec primary pki nss-cert-import \
    --cert ds_server.crt \
    Server-Cert

docker exec primary pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create DS server cert in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import DS certs into primary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pk12util \
    -d /root/.dogtag/nssdb \
    -o $SHARED/primaryds_server.p12 \
    -W Secret.123 \
    -n Server-Cert

sudo chmod go+r primaryds_server.p12

tests/bin/ds-certs-import.sh \
    --image=${DS_IMAGE} \
    --input=primaryds_server.p12 \
    --password=Secret.123 \
    primaryds

tests/bin/ds-stop.sh \
    --image=${DS_IMAGE} \
    primaryds

tests/bin/ds-start.sh \
    --image=${DS_IMAGE} \
    primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import DS certs into primary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-secure-ds-primary.cfg \
    -s CA \
    -D pki_ds_url=ldaps://primaryds.example.com:3636 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check NSS database in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# NSS database should contain DS cert and PKI certs
docker exec primary pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find \
    | tee output

sed -n \
    -e 's/^ *\(Nickname: .*\)$/\1/p' \
    -e 's/^ *\(Trust Flags: .*\)$/\1/p' \
    -e 's/^$//p' \
    output > actual

cat > expected << EOF
Nickname: ds_signing
Trust Flags: CT,C,C

Nickname: ca_signing
Trust Flags: CTu,Cu,Cu

Nickname: ca_ocsp_signing
Trust Flags: u,u,u

Nickname: sslserver
Trust Flags: u,u,u

Nickname: subsystem
Trust Flags: u,u,u

Nickname: ca_audit_signing
Trust Flags: u,u,Pu
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check NSS database in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create external cert in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki \
    nss-cert-request \
    --subject "CN=External Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr external.csr

docker exec primary pki \
    nss-cert-issue \
    --csr external.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert external.crt

docker exec primary pki nss-cert-import \
    --cert external.crt \
    --trust CT,C,C \
    external

docker exec primary pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create external cert in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import external cert into primary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server \
    instance-externalcert-add \
    --cert-file external.crt \
    --nickname external \
    --trust-args CT,C,C

# NSS database should contain the external cert
docker exec primary pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-show \
    external \
    | tee output

sed -n \
    -e 's/^ *\(Nickname: .*\)$/\1/p' \
    -e 's/^ *\(Trust Flags: .*\)$/\1/p' \
    output > actual

cat > expected << EOF
Nickname: external
Trust Flags: CT,C,C
EOF

diff expected actual

# external_certs.conf should contain the external cert
docker exec primary cat /etc/pki/pki-tomcat/external_certs.conf | tee output

cat > expected << EOF
0.nickname=external
0.token=internal
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import external cert into primary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify DS connection in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-db-config-show | tee output

echo "primaryds.example.com" > expected
sed -n 's/^\s\+Hostname:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual

echo "3636" > expected
sed -n 's/^\s\+Port:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual

echo "true" > expected
sed -n 's/^\s\+Secure:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify DS connection in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify users and DS hosts in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec primary pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123

docker exec primary pki -n caadmin ca-user-find
docker exec primary pki securitydomain-host-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify users and DS hosts in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki -n caadmin ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in primary CA (rc=$_rc)" >&2
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

step "Import DS signing cert into secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki \
    pkcs12-export \
    --pkcs12 $SHARED/ds_signing.p12 \
    --password Secret.123 \
    Self-Signed-CA

docker exec secondary pki \
    pkcs12-import \
    --pkcs12 $SHARED/ds_signing.p12 \
    --password Secret.123

docker exec secondary pki \
    nss-cert-export \
    --output-file ds_signing.crt \
    Self-Signed-CA

docker exec secondary pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import DS signing cert into secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create DS server cert in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki \
    nss-cert-request \
    --subject "CN=secondaryds.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr ds_server.csr

docker exec secondary pki \
    nss-cert-issue \
    --issuer Self-Signed-CA \
    --csr ds_server.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert ds_server.crt

docker exec secondary pki nss-cert-import \
    --cert ds_server.crt \
    Server-Cert

docker exec secondary pki nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create DS server cert in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import DS certs into secondary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pk12util \
    -d /root/.dogtag/nssdb \
    -o $SHARED/secondaryds_server.p12 \
    -W Secret.123 \
    -n Server-Cert

sudo chmod go+r secondaryds_server.p12

tests/bin/ds-certs-import.sh \
    --image=${DS_IMAGE} \
    --input=secondaryds_server.p12 \
    --password=Secret.123 \
    secondaryds

tests/bin/ds-stop.sh \
    --image=${DS_IMAGE} \
    secondaryds

tests/bin/ds-start.sh \
    --image=${DS_IMAGE} \
    secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import DS certs into secondary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export certs for cloning from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec primary pki-server \
    cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

# export PKI certs including external cert but without sslserver cert
docker exec primary pki-server \
    ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec primary pki \
    pkcs12-cert-find \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --password Secret.123 \
    | tee output

sed -n \
    -e 's/^ *\(Friendly Name: .*\)$/\1/p' \
    -e 's/^ *\(Trust Flags: .*\)$/\1/p' \
    -e 's/^$//p' \
    output > actual

cat > expected << EOF
Friendly Name: subsystem
Trust Flags: u,u,u

Friendly Name: ca_signing
Trust Flags: CTu,Cu,Cu

Friendly Name: ca_ocsp_signing
Trust Flags: u,u,u

Friendly Name: ca_audit_signing
Trust Flags: u,u,Pu

Friendly Name: external
Trust Flags: CT,C,C
EOF

diff expected actual

# export external_certs.conf
docker cp primary:/etc/pki/pki-tomcat/external_certs.conf .
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export certs for cloning from primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# install secondary CA with the same DS cert, PKI certs, and external cert
docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-secure-ds-secondary.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/ca-certs.p12 \
    -D pki_ds_url=ldaps://secondaryds.example.com:3636 \
    -D pki_server_external_certs_path=$SHARED/external_certs.conf \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check NSS database in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# NSS database should contain DS cert, PKI certs, and external cert
docker exec secondary pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find \
    | tee output

sed -n \
    -e 's/^ *\(Nickname: .*\)$/\1/p' \
    -e 's/^ *\(Trust Flags: .*\)$/\1/p' \
    -e 's/^$//p' \
    output > actual

cat > expected << EOF
Nickname: subsystem
Trust Flags: u,u,u

Nickname: ca_signing
Trust Flags: CTu,Cu,Cu

Nickname: ca_ocsp_signing
Trust Flags: u,u,u

Nickname: ca_audit_signing
Trust Flags: u,u,Pu

Nickname: external
Trust Flags: CT,C,C

Nickname: ds_signing
Trust Flags: CT,C,C

Nickname: sslserver
Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check NSS database in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check external cert in secondary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# external_certs.conf should contain the external cert
docker exec secondary cat /etc/pki/pki-tomcat/external_certs.conf | tee output

cat > expected << EOF
0.nickname=external
0.token=internal
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external cert in secondary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in primary PKI container"
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
    echo "FAIL: Run PKI healthcheck in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in secondary PKI container"
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
    echo "FAIL: Run PKI healthcheck in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify DS connection in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-db-config-show | tee output

echo "secondaryds.example.com" > expected
sed -n 's/^\s\+Hostname:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual

echo "3636" > expected
sed -n 's/^\s\+Port:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual

echo "true" > expected
sed -n 's/^\s\+Secure:\s\+\(\S\+\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify DS connection in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify users and SD hosts in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED/ca_admin_cert.p12

docker exec secondary pki-server \
    cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec secondary pki \
    nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec secondary pki \
    pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123

docker exec secondary pki -n caadmin ca-user-find
docker exec secondary pki securitydomain-host-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify users and SD hosts in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki -n caadmin ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
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

step "Re-install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert bundle containing CA and DS signing certs
docker exec secondary sed \
    -n wcert_bundle.pem \
    $SHARED/ca_signing.crt \
    ds_signing.crt
docker exec secondary cat cert_bundle.pem

# re-install secondary CA with cert bundle, PKI certs, and external cert
docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-secure-ds-secondary.cfg \
    -s CA \
    -D pki_cert_chain_path=cert_bundle.pem \
    -D pki_clone_pkcs12_path=$SHARED/ca-certs.p12 \
    -D pki_ds_url=ldaps://secondaryds.example.com:3636 \
    -D pki_server_external_certs_path=$SHARED/external_certs.conf \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Re-install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check NSS database in secondary PKI container again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# NSS database should contain DS cert, PKI certs, and external cert
docker exec secondary pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-find \
    | tee output

sed -n \
    -e 's/^ *\(Nickname: .*\)$/\1/p' \
    -e 's/^ *\(Trust Flags: .*\)$/\1/p' \
    -e 's/^$//p' \
    output > actual

cat > expected << EOF
Nickname: subsystem
Trust Flags: u,u,u

Nickname: ca_signing
Trust Flags: CTu,Cu,Cu

Nickname: ca_ocsp_signing
Trust Flags: u,u,u

Nickname: ca_audit_signing
Trust Flags: u,u,Pu

Nickname: external
Trust Flags: CT,C,C

Nickname: ds_signing
Trust Flags: CT,C,C

Nickname: sslserver
Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check NSS database in secondary PKI container again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove external cert from secondary PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server \
    instance-externalcert-del \
    --nickname external

# NSS database should not contain the external cert
docker exec secondary pki \
    -d /etc/pki/pki-tomcat/alias \
    -f /etc/pki/pki-tomcat/password.conf \
    nss-cert-show \
    external \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ERROR: Certificate not found: external
EOF

diff expected stderr

# external_certs.conf should be removed
docker exec secondary cat /etc/pki/pki-tomcat/external_certs.conf \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
cat: /etc/pki/pki-tomcat/external_certs.conf: No such file or directory
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove external cert from secondary PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from secondary PKI container"
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
    echo "FAIL: Remove CA from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from primary PKI container"
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
    echo "FAIL: Remove CA from primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-secure-ds-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-secure-ds-test PASSED ===="
