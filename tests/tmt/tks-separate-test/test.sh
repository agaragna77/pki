#!/bin/bash
# Generated TMT port of .github/workflows/tks-separate-test.yml
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
    docker rm -f ca cads tks tksds 2>/dev/null || true
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

step "Install banner in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in CA container (rc=$_rc)" >&2
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

step "Set up TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=tks.example.com \
    --network=example \
    --network-alias=tks.example.com \
    tks
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TKS in TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt
docker exec ca cp /root/.dogtag/pki-tomcat/ca_admin.cert ${SHARED}/ca_admin.cert
docker exec tks pkispawn \
    -f /usr/share/pki/server/examples/installation/tks.cfg \
    -s TKS \
    -D pki_security_domain_hostname=ca.example.com \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_admin_cert_file=${SHARED}/ca_admin.cert \
    -D pki_ds_url=ldap://tksds.example.com:3389 \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TKS in TKS container (rc=$_rc)" >&2
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

step "Check TKS certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in TKS container (rc=$_rc)" >&2
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
    docker exec tks pki-healthcheck --failures-only
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

step "Verify TKS admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca cp /root/.dogtag/pki-tomcat/ca_admin_cert.p12 ${SHARED}/ca_admin_cert.p12

docker exec tks pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec tks pki pkcs12-import \
    --pkcs12 ${SHARED}/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec tks pki -n caadmin --ignore-banner tks-user-show tksadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify TKS admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pkidestroy \
    -s TKS \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TKS (rc=$_rc)" >&2
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
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
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

step "Check CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA systemd journal (rc=$_rc)" >&2
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

step "Check TKS systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== tks-separate-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== tks-separate-test PASSED ===="
