#!/bin/bash
# Generated TMT port of .github/workflows/subca-basic-test.yml
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
    docker rm -f root subordinate 2>/dev/null || true
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

step "Set up root DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=rootds.example.com \
    --network=example \
    --network-alias=rootds.example.com \
    --password=Secret.123 \
    rootds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up root PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=root.example.com \
    --network=example \
    --network-alias=root.example.com \
    root
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install root CA in root container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://rootds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install root CA in root container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pki-server status | tee output

# root CA should be a domain manager
echo "True" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in root container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in root container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up subordinate DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=subds.example.com \
    --network=example \
    --network-alias=subds.example.com \
    --password=Secret.123 \
    subds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up subordinate DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up subordinate PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=sub.example.com \
    --network=example \
    --network-alias=sub.example.com \
    subordinate
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up subordinate PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install subordinate CA in subordinate container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pki-server cert-export ca_signing --cert-file ${SHARED}/root-ca_signing.crt
docker exec subordinate pkispawn \
    -f /usr/share/pki/server/examples/installation/subca.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/root-ca_signing.crt \
    -D pki_ds_url=ldap://subds.example.com:3389 \
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install subordinate CA in subordinate container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server status | tee output

# sub CA should not be a domain manager
echo "False" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in subordinate container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in subordinate container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export ca_signing \
    --cert-file ca_signing.crt
docker exec subordinate openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_signing.csr

# check sub CA signing cert extensions
docker exec subordinate /usr/share/pki/tests/ca/bin/test-subca-signing-cert-ext.sh ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export ca_ocsp_signing \
    --cert-file ca_ocsp_signing.crt
docker exec subordinate openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_ocsp_signing.csr
docker exec subordinate openssl x509 -text -noout -in ca_ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export subsystem \
    --cert-file subsystem.crt
docker exec subordinate openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr
docker exec subordinate openssl x509 -text -noout -in subsystem.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export sslserver \
    --cert-file sslserver.crt
docker exec subordinate openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr
docker exec subordinate openssl x509 -text -noout -in sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
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
    docker exec subordinate pki-healthcheck \
        --failures-only \
        --debug \
        > >(tee stdout) 2> >(tee stderr >&2)
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

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Verify CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec subordinate pki nss-cert-import \
    --cert ca_signing.crt \
    ca_signing

docker exec subordinate pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

docker exec subordinate pki -n caadmin --ignore-banner ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in subordinate CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki -n caadmin --ignore-banner ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in subordinate CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check integrate root OCSP validation from SubCA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > expected << EOF
Chain is good!
Root Certificate Subject:: "CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE"
Certificate 1 Subject: "CN=Subordinate CA Signing Certificate,O=EXAMPLE"
EOF

docker exec subordinate /usr/lib64/nss/unsupported-tools/vfychain -v -d /etc/pki/pki-tomcat/alias -w Secret.123 -u 11 -a -p -p -g leaf -h requireFreshInfo -m ocsp -s failIfNoInfo ca_signing.crt 2>&1 | tee actual
diff expected actual

docker exec subordinate /usr/lib64/nss/unsupported-tools/vfychain -v -d /root/.dogtag/nssdb/ -u 11 -a -p -p -g leaf -h requireFreshInfo -m ocsp -s failIfNoInfo ca_signing.crt 2>&1 | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check integrate root OCSP validation from SubCA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove subordinate CA from subordinate container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove subordinate CA from subordinate container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove root CA from root container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove root CA from root container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== subca-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== subca-basic-test PASSED ===="
