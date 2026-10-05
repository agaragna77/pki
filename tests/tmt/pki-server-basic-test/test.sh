#!/bin/bash
# Generated TMT port of .github/workflows/pki-server-basic-test.yml
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
    docker rm -f pki 2>/dev/null || true
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

step "Set up runner container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki.example.com \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up runner container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server
docker exec pki pki-server --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server --version
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI with wrong option"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server --wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

sed -n \
    -e '/^pki-server:/p' \
    stderr > actual

cat > expected << EOF
pki-server: error: unrecognized arguments: --wrong
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI with wrong option (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI with wrong sub-command"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ERROR: Invalid module "wrong".
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI with wrong sub-command (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server instance help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server instance-find --help
docker exec pki pki-server instance-show --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server instance help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server password help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server password-find --help
docker exec pki pki-server password-set --help
docker exec pki pki-server password-unset --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server password help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server cert help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-find --help
docker exec pki pki-server cert-show --help
docker exec pki pki-server cert-validate --help
docker exec pki pki-server cert-update --help
docker exec pki pki-server cert-request --help
docker exec pki pki-server cert-create --help
docker exec pki pki-server cert-import --help
docker exec pki pki-server cert-export --help
docker exec pki pki-server cert-del --help
docker exec pki pki-server cert-fix --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server cert help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server http-connector help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server http-connector-find --help
docker exec pki pki-server http-connector-show --help
docker exec pki pki-server http-connector-add --help
docker exec pki pki-server http-connector-mod --help
docker exec pki pki-server http-connector-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server http-connector help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server http-connector-host help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server http-connector-host-find --help
docker exec pki pki-server http-connector-host-show --help
docker exec pki pki-server http-connector-host-add --help
docker exec pki pki-server http-connector-host-mod --help
docker exec pki pki-server http-connector-host-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server http-connector-host help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server http-connector-cert help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server http-connector-cert-find --help
docker exec pki pki-server http-connector-cert-add --help
docker exec pki pki-server http-connector-cert-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server http-connector-cert help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server webapp help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server webapp-find --help
docker exec pki pki-server webapp-show --help
docker exec pki pki-server webapp-deploy --help
docker exec pki pki-server webapp-undeploy --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server webapp help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server subsystem help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server subsystem-find --help
docker exec pki pki-server subsystem-show --help
docker exec pki pki-server subsystem-enable --help
docker exec pki pki-server subsystem-disable --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server subsystem help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-sd help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-sd-create --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-sd help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-sd-subsystem help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-sd-subsystem-find --help
docker exec pki pki-server ca-sd-subsystem-add --help
docker exec pki pki-server ca-sd-subsystem-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-sd-subsystem help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-config help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find --help
docker exec pki pki-server ca-config-show --help
docker exec pki pki-server ca-config-set --help
docker exec pki pki-server ca-config-unset --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-config help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-user help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-find --help
docker exec pki pki-server ca-user-show --help
docker exec pki pki-server ca-user-add --help
docker exec pki pki-server ca-user-mod --help
docker exec pki pki-server ca-user-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-user help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-user-cert help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-cert-find --help
docker exec pki pki-server ca-user-cert-add --help
docker exec pki pki-server ca-user-cert-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-user-cert help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-user-role help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-find --help
docker exec pki pki-server ca-user-role-add --help
docker exec pki pki-server ca-user-role-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-user-role help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-group help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-group-find --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-group help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-group-member help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-group-member-find --help
docker exec pki pki-server ca-group-member-add --help
docker exec pki pki-server ca-group-member-del --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-group-member help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-id-generator help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-id-generator-show --help
docker exec pki pki-server ca-id-generator-update --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-id-generator help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-db-access help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-db-access-grant --help
docker exec pki pki-server ca-db-access-revoke --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-db-access help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-audit-config help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-audit-config-show --help
docker exec pki pki-server ca-audit-config-mod --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-audit-config help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-audit-event help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-audit-event-find --help
docker exec pki pki-server ca-audit-event-show --help
docker exec pki pki-server ca-audit-event-enable --help
docker exec pki pki-server ca-audit-event-disable --help
docker exec pki pki-server ca-audit-event-update --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-audit-event help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-audit-file help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-audit-file-find --help
docker exec pki pki-server ca-audit-file-verify --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-audit-file help messages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== pki-server-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== pki-server-basic-test PASSED ===="
