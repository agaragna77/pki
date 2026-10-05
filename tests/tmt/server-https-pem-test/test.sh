#!/bin/bash
# Generated TMT port of .github/workflows/server-https-pem-test.yml
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
    docker rm -f client pki 2>/dev/null || true
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

step "Set up server container"
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
    echo "FAIL: Set up server container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki openssl req \
    -newkey rsa:2048 \
    -x509 \
    -nodes \
    -days 365 \
    -subj "/CN=$HOSTNAME" \
    -keyout /var/lib/pki/pki-tomcat/conf/sslserver.key \
    -out /var/lib/pki/pki-tomcat/conf/sslserver.crt
docker exec pki chown pkiuser:pkiuser /var/lib/pki/pki-tomcat/conf/sslserver.crt
docker exec pki chmod 660 /var/lib/pki/pki-tomcat/conf/sslserver.crt
docker exec pki chown pkiuser:pkiuser /var/lib/pki/pki-tomcat/conf/sslserver.key
docker exec pki chmod 660 /var/lib/pki/pki-tomcat/conf/sslserver.key
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create HTTPS connector with PEM files"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server http-connector-add \
    --port 8443 \
    --scheme https \
    --secure true \
    --sslEnabled true \
    --sslProtocol SSL \
    Secure
docker exec pki pki-server http-connector-cert-add \
    --certFile /var/lib/pki/pki-tomcat/conf/sslserver.crt \
    --keyFile /var/lib/pki/pki-tomcat/conf/sslserver.key
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create HTTPS connector with PEM files (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server start
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start PKI server (rc=$_rc)" >&2
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
    --network-alias=client.example.com \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for PKI server to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://pki.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for PKI server to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server stop --wait -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server remove -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== server-https-pem-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== server-https-pem-test PASSED ===="
