#!/bin/bash
# Build pki-runner the same way GHA Build PKI does for the runner used by
# ca-basic-test (see .github/workflows/build.yml → target pki-runner).
#
# Defaults match tests/bin/test-init.sh (BASE_IMAGE + COPR_REPO=@pki/master
# on non-release branches) so the builder gets a JSS new enough for current
# master (e.g. JSSTrustManager.setTokenName).
set -euo pipefail

REPO_ROOT="${1:-${TMT_TREE:-}}"
if [[ -z "$REPO_ROOT" || ! -f "$REPO_ROOT/Dockerfile" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
cd "$REPO_ROOT"

if [[ "${SKIP_PKI_BUILD:-0}" == "1" ]]; then
    echo "SKIP_PKI_BUILD=1 — not building (image must already exist)"
    docker image inspect pki-runner >/dev/null
    exit 0
fi

command -v docker >/dev/null \
    || { echo "ERROR: docker required to build pki-runner" >&2; exit 1; }

# --- same defaults as tests/bin/test-init.sh ---
release_branch='^v[0-9]+\.[0-9]+$'
release_branch_with_suffix='^v[0-9]+\.[0-9]+-.*$'

if [[ -z "${BRANCH_NAME:-}" ]]; then
    BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)
fi

if [[ -z "${BASE_IMAGE:-}" ]]; then
    if [[ "$BRANCH_NAME" =~ ^v11\.9$ ]] \
            || [[ "$BRANCH_NAME" =~ ^v11\.9-.*$ ]]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:44
    elif [[ "$BRANCH_NAME" =~ $release_branch ]] \
            || [[ "$BRANCH_NAME" =~ $release_branch_with_suffix ]]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:rawhide
    else
        BASE_IMAGE=registry.fedoraproject.org/fedora:latest
    fi
fi

if [[ -z "${COPR_REPO:-}" ]]; then
    if [[ "$BRANCH_NAME" =~ $release_branch ]] \
            || [[ "$BRANCH_NAME" =~ $release_branch_with_suffix ]]; then
        COPR_REPO=""
    else
        # Development branches: COPR supplies newer JSS/ldapjdk than Fedora.
        COPR_REPO=@pki/master
    fi
fi

BUILD_OPTS="${BUILD_OPTS:-}"

BUILD_ARGS=(
    --build-arg "BASE_IMAGE=${BASE_IMAGE}"
    --build-arg "COPR_REPO=${COPR_REPO}"
    --build-arg "BUILD_OPTS=${BUILD_OPTS}"
)

echo "==== Building PKI images (GHA Build PKI equivalent) ===="
echo "BRANCH_NAME=${BRANCH_NAME}"
echo "BASE_IMAGE=${BASE_IMAGE}"
echo "COPR_REPO=${COPR_REPO:-<none>}"
echo "workdir=${REPO_ROOT}"

# Refresh images the Dockerfile COPY --from / FROM (avoid stale local :latest).
echo "==== Pulling base / jss-dist / ldapjdk-dist ===="
docker pull "$BASE_IMAGE"
docker pull quay.io/dogtagpki/jss-dist:latest
docker pull quay.io/dogtagpki/ldapjdk-dist:latest

# Match GHA: produce tag "pki-runner" (runner-init.sh default).
# --pull refreshes FROM stages; COPY --from uses the pulled jss/ldapjdk above.
docker build \
    --pull \
    "${BUILD_ARGS[@]}" \
    --target pki-runner \
    -t pki-runner \
    -t pki-runner:latest \
    .

docker image inspect pki-runner >/dev/null
echo "==== pki-runner image ready ===="
docker images pki-runner
