#!/bin/bash
# Generated TMT port of .github/workflows/tps-clone-test.yml
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
    docker rm -f primary primaryds secondary secondaryds 2>/dev/null || true
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

step "Install CA in primary PKI container"
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
    echo "FAIL: Install CA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in primary PKI container"
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
    echo "FAIL: Install KRA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TKS in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/tks.cfg \
    -s TKS \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -v

docker exec primary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TKS in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TPS in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/tps.cfg \
    -s TPS \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -D pki_authdb_url=ldap://primaryds.example.com:3389 \
    -D pki_enable_server_side_keygen=True \
    -v

docker exec primary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TPS in primary PKI container (rc=$_rc)" >&2
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

step "Install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt

docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/ca-certs.p12 \
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
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/kra-certs.p12 \
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

step "Install TKS in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server tks-clone-prepare \
    --pkcs12-file $SHARED/tks-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/tks-clone.cfg \
    -s TKS \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/tks-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -v

docker exec secondary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TKS in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TPS in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server tps-clone-prepare \
    --pkcs12-file $SHARED/tps-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/tps-clone.cfg \
    -s TPS \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_clone_pkcs12_path=${SHARED}/tps-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -D pki_authdb_url=ldap://secondaryds.example.com:3389 \
    -D pki_enable_server_side_keygen=True \
    -v

docker exec secondary pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TPS in secondary PKI container (rc=$_rc)" >&2
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

step "Check admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary cp /root/.dogtag/pki-tomcat/ca_admin_cert.p12 ${SHARED}/ca_admin_cert.p12

docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec secondary pki pkcs12-import \
    --pkcs12 ${SHARED}/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec secondary pki -n caadmin tps-user-show tpsadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TPS from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s TPS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TPS from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TKS from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s TKS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TKS from secondary PKI container (rc=$_rc)" >&2
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

step "Remove TPS from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s TPS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TPS from primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TKS from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s TKS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TKS from primary PKI container (rc=$_rc)" >&2
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

step "Check primary TKS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary TKS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary TPS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/tps -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary TPS debug log (rc=$_rc)" >&2
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

step "Check secondary TKS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary TKS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary TPS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/tps -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary TPS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== tps-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== tps-clone-test PASSED ===="
