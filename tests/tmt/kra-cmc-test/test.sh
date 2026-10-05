#!/bin/bash
# Generated TMT port of .github/workflows/kra-cmc-test.yml
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
    docker rm -f ca kra 2>/dev/null || true
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

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=ca.example.com \
    --network=example \
    --network-alias=ca.example.com \
    ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://cads.example.com:3389 \
    -v

docker exec ca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize CA admin in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file $SHARED/ca_signing.crt

docker exec ca pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize CA admin in CA container (rc=$_rc)" >&2
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

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=kra.example.com \
    --network=example \
    --network-alias=kra.example.com \
    kra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in KRA container (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-external-certs-step1.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://krads.example.com:3389 \
    -D pki_storage_csr_path=$SHARED/kra_storage.csr \
    -D pki_transport_csr_path=$SHARED/kra_transport.csr \
    -D pki_subsystem_csr_path=$SHARED/subsystem.csr \
    -D pki_sslserver_csr_path=$SHARED/sslserver.csr \
    -D pki_audit_signing_csr_path=$SHARED/kra_audit_signing.csr \
    -D pki_admin_csr_path=$SHARED/kra_admin.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in KRA container (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA storage cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/kra_storage.csr

# create CMC request
docker exec ca cp $SHARED/kra_storage.csr kra_storage.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/kra_storage-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/kra_storage-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i kra_storage.cmc-response \
    -o $SHARED/kra_storage.p7b

# check issued cert chain
docker exec ca openssl pkcs7 -print_certs -in $SHARED/kra_storage.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA storage cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA transport cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/kra_transport.csr

# create CMC request
docker exec ca cp $SHARED/kra_transport.csr kra_transport.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/kra_transport-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/kra_transport-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i kra_transport.cmc-response \
    -o $SHARED/kra_transport.p7b

# check issued cert chain
docker exec ca openssl pkcs7 -print_certs -in $SHARED/kra_transport.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA transport cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subsystem cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/subsystem.csr

# create CMC request
docker exec ca cp $SHARED/subsystem.csr subsystem.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/subsystem-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/subsystem-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i subsystem.cmc-response \
    -o $SHARED/subsystem.p7b

# check issued cert chain
docker exec ca openssl pkcs7 -print_certs -in $SHARED/subsystem.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue subsystem cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/sslserver.csr

# create CMC request
docker exec ca cp $SHARED/sslserver.csr sslserver.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/sslserver-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/sslserver-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i sslserver.cmc-response \
    -o $SHARED/sslserver.p7b

# check issued cert chain
docker exec ca openssl pkcs7 -print_certs -in $SHARED/sslserver.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA audit signing cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/kra_audit_signing.csr

# create CMC request
docker exec ca cp $SHARED/kra_audit_signing.csr audit_signing.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/audit_signing-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/audit_signing-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i audit_signing.cmc-response \
    -o $SHARED/kra_audit_signing.p7b

# check issued cert chain
docker exec ca openssl pkcs7 -print_certs -in $SHARED/kra_audit_signing.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA audit signing cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA admin cert with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec ca openssl req -text -noout -in $SHARED/kra_admin.csr

# create CMC request
docker exec ca cp $SHARED/kra_admin.csr admin.csr
docker exec ca CMCRequest \
    /usr/share/pki/server/examples/cmc/admin-cmc-request.cfg

# submit CMC request
docker exec ca HttpClient \
    /usr/share/pki/server/examples/cmc/admin-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec ca CMCResponse \
    -d /root/.dogtag/nssdb \
    -i admin.cmc-response \
    -o kra_admin.p7b

# pki_admin_cert_path only supports a single cert so the admin cert
# needs to be exported from the PKCS #7 cert chain
# TODO: fix pki_admin_cert_path to support PKCS #7 cert chain
docker exec ca pki pkcs7-cert-export \
    --pkcs7 kra_admin.p7b \
    --output-prefix kra_admin- \
    --output-suffix .crt
docker exec ca cp kra_admin-1.crt $SHARED/kra_admin.crt

# check issued cert
docker exec ca openssl x509 -text -noout -in $SHARED/kra_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA admin cert with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in KRA container (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-external-certs-step2.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://krads.example.com:3389 \
    -D pki_storage_csr_path=$SHARED/kra_storage.csr \
    -D pki_transport_csr_path=$SHARED/kra_transport.csr \
    -D pki_subsystem_csr_path=$SHARED/subsystem.csr \
    -D pki_sslserver_csr_path=$SHARED/sslserver.csr \
    -D pki_audit_signing_csr_path=$SHARED/kra_audit_signing.csr \
    -D pki_admin_csr_path=$SHARED/kra_admin.csr \
    -D pki_storage_cert_path=$SHARED/kra_storage.p7b \
    -D pki_transport_cert_path=$SHARED/kra_transport.p7b \
    -D pki_subsystem_cert_path=$SHARED/subsystem.p7b \
    -D pki_sslserver_cert_path=$SHARED/sslserver.p7b \
    -D pki_audit_signing_cert_path=$SHARED/kra_audit_signing.p7b \
    -D pki_admin_cert_path=$SHARED/kra_admin.crt \
    -v

docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in KRA container (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec kra pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/kra_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec kra pki -n kraadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA from KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA from KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server systemd journal in CA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server systemd journal in KRA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-cmc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-cmc-test PASSED ===="
