#!/bin/bash
# Generated TMT port of .github/workflows/kra-kryoptic-test.yml
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

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec pki sed -n 's/^VERSION_ID=//p' /etc/os-release)
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

step "Configure crypto-policies"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec pki sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure crypto-policies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install Kryoptic"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# install OpenDNSSEC to ensure no conflicts
# https://github.com/dogtagpki/pki/issues/5045
docker exec pki dnf install -y kryoptic opensc opendnssec

docker exec pki rpm -ql kryoptic
docker exec pki cat /usr/share/p11-kit/modules/kryoptic.module

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec pki pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --show-info || true

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec pki pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots || true

# check with NSS
docker exec pki modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install Kryoptic (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file for HSM
echo "Secret.HSM" > password.hsm

# configure token
docker exec pki runuser -u pkiuser -- \
    mkdir -p /home/pkiuser/.config/kryoptic

docker exec -i pki runuser -u pkiuser -- \
    tee /home/pkiuser/.config/kryoptic/token.conf << EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/home/pkiuser/.config/kryoptic/token.sql"
objects_dedup = "TrustOnly"
EOF

# check with OpenSC
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# initialize token and SO PIN
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --label HSM \
    --so-pin $(cat password.hsm) \
    --init-token

# initialize user PIN
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --login \
    --login-type so \
    --so-pin $(cat password.hsm) \
    --pin $(cat password.hsm) \
    --init-pin

# check with OpenSC
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# check with NSS
docker exec pki runuser -u pkiuser -- \
    modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_server_database_password=Secret.123 \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_admin_nickname=admin \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find \
    | tee output

# there should be 0 certs
echo "0" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find \
    | tee output

# there should be 5 certs
echo "5" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA with HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-pqc.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_server_database_password=Secret.123 \
    -D pki_storage_token=HSM \
    -D pki_transport_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_admin_nickname=admin \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA with HSM (rc=$_rc)" >&2
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

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find \
    | tee output

# there should be 0 certs
echo "0" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find \
    | tee output

# there should be 8 certs
echo "8" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check kra_storage cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:kra_storage \
    | tee output

# trust attributes should be u,u,u
echo "u,u,u" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname HSM:kra_storage \
    | tee output

# key type and algorithm should be ML-KEM
cat > expected << EOF
Type: ML-KEM-768
Algorithm: ML-KEM
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-verify \
    --cert-usage SSLClient \
    HSM:kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check kra_storage cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check kra_transport cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:kra_transport \
    | tee output

# trust attributes should be u,u,u
echo "u,u,u" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname HSM:kra_transport \
    | tee output

# key type and algorithm should be ML-KEM
cat > expected << EOF
Type: ML-KEM-768
Algorithm: ML-KEM
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-verify \
    --cert-usage SSLClient \
    HSM:kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check kra_transport cert in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check kra_audit_signing cert in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-show \
    HSM:kra_audit_signing \
    | tee output

# trust attributes should be u,u,Pu
echo "u,u,Pu" > expected
sed -n 's/\s*Trust Flags:\s*\(\S\+\)\s*$/\1/p' output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-key-find \
    --nickname HSM:kra_audit_signing \
    | tee output

# key type and algorithm should be ML-DSA
cat > expected << EOF
Type: ML-DSA-65
Algorithm: ML-DSA
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    nss-cert-verify \
    --cert-usage ObjectSigner \
    HSM:kra_audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check kra_audit_signing cert in HSM (rc=$_rc)" >&2
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
    # pki-healthcheck fails due to trust attributes issue in Kryoptic
    # https://github.com/latchset/kryoptic/issues/450
    docker exec pki runuser -u pkiuser -- \
        pki-healthcheck --failures-only || true
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

step "Check admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123

docker exec pki pki nss-key-find \
    --nickname admin \
    | tee output

# key type and algorithm should be ML-DSA
cat > expected << EOF
Type: ML-DSA-65
Algorithm: ML-DSA
EOF

sed -n \
    -e 's/\s*\(Type:\s*\S\+\)\s*$/\1/p' \
    -e 's/\s*\(Algorithm:\s*\S\+\)\s*$/\1/p' \
    output > actual

diff expected actual

docker exec pki pki nss-cert-verify \
    --cert-usage SSLClient \
    admin

docker exec pki pki -n admin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy \
    -s KRA \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA (rc=$_rc)" >&2
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

step "Remove Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    rm -rf /home/pkiuser/.config/kryoptic
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -l
docker exec pki find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for PKI core dumps (rc=$_rc)" >&2
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-kryoptic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-kryoptic-test PASSED ===="
