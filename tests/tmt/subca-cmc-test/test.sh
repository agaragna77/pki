#!/bin/bash
# Generated TMT port of .github/workflows/subca-cmc-test.yml
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
    -D pki_security_domain_name=ROOT \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install root CA in root container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update caCMCcaCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Reduce policyset.caCertSet.2.default.params.range such that
# it generates a subordinate CA cert with shorter validity
# which will not violate the CAValidityConstraint.
docker exec root sed -i \
    -e "s/\(policyset.caCertSet.2.default.params.range\)=.*/\1=7300/" \
    /var/lib/pki/pki-tomcat/ca/profiles/ca/caCMCcaCert.cfg

# restart CA subsystem
docker exec root pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update caCMCcaCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install root CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pki-server cert-export ca_signing --cert-file $SHARED/root-ca_signing.crt

docker exec root pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec root pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec root pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install root CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec root pki -n caadmin ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in root CA (rc=$_rc)" >&2
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

step "Install subordinate CA in subordinate container (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step1.cfg \
    -s CA \
    -D pki_ds_url=ldap://subds.example.com:3389 \
    -D pki_ca_signing_csr_path=$SHARED/ca_signing.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install subordinate CA in subordinate container (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subordinate CA signing cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec root openssl req -text -noout -in $SHARED/ca_signing.csr

# create CMC request
docker exec root cp $SHARED/ca_signing.csr ca_signing.csr
docker exec root CMCRequest \
    /usr/share/pki/server/examples/cmc/ca_signing-cmc-request.cfg

# submit CMC request
docker exec root HttpClient \
    /usr/share/pki/server/examples/cmc/ca_signing-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec root CMCResponse \
    -d /root/.dogtag/nssdb \
    -i ca_signing.cmc-response \
    -o $SHARED/ca_signing.p7b

# check issued cert chain
docker exec root openssl pkcs7 -print_certs -in $SHARED/ca_signing.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue subordinate CA signing cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install subordinate CA in subordinate container (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step2.cfg \
    -s CA \
    -D pki_ds_url=ldap://subds.example.com:3389 \
    -D pki_cert_chain_path=$SHARED/root-ca_signing.crt \
    -D pki_ca_signing_csr_path=$SHARED/ca_signing.csr \
    -D pki_ca_signing_cert_path=$SHARED/ca_signing.p7b \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install subordinate CA in subordinate container (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export ca_signing --cert-file ca_signing.crt

# check sub CA signing cert extensions
docker exec subordinate /usr/share/pki/tests/ca/bin/test-subca-signing-cert-ext.sh ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export ca_ocsp_signing --cert-file ca_ocsp_signing.crt
docker exec subordinate openssl x509 -text -noout -in ca_ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export ca_audit_signing --cert-file ca_audit_signing.crt
docker exec subordinate openssl x509 -text -noout -in ca_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export subsystem --cert-file subsystem.crt
docker exec subordinate openssl x509 -text -noout -in subsystem.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki-server cert-export sslserver --cert-file sslserver.crt
docker exec subordinate openssl x509 -text -noout -in sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subordinate CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subordinate CA admin cert (rc=$_rc)" >&2
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
    docker exec subordinate pki-healthcheck --failures-only
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

step "Verify subordinate CA admin cert"
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

docker exec subordinate pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify subordinate CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert requests in subordinate CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subordinate pki -n caadmin ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert requests in subordinate CA (rc=$_rc)" >&2
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
    echo "==== subca-cmc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== subca-cmc-test PASSED ===="
