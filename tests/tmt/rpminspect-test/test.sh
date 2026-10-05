#!/bin/bash
# Generated TMT port of .github/workflows/rpminspect-test.yml
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

step "Set up PKI container"
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
    echo "FAIL: Set up PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install rpminspect"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y rpminspect-data-fedora
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install rpminspect (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Copy SRPM and RPM packages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker create --name=pki-dist pki-dist

mkdir /tmp/build
docker cp pki-dist:/root/SRPMS/. /tmp/build/SRPMS
docker cp pki-dist:/root/RPMS/. /tmp/build/RPMS
ls -lR /tmp/build

docker exec pki mkdir -p build
docker cp /tmp/build/. pki:build/
docker exec pki ls -lR build

docker rm -f pki-dist

# get RPM version and release number
VERSION=$(docker exec pki ls build/SRPMS | sed -e 's/^pki-\(.*\)\.src\.rpm$/\1/')
echo "VERSION: $VERSION"
echo "$VERSION" > VERSION
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Copy SRPM and RPM packages (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install rpminspect profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -lR /usr/share/rpminspect/profiles
docker exec pki cp \
    /usr/share/pki/tests/pki-rpminspect.yaml \
    /usr/share/rpminspect/profiles/fedora
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install rpminspect profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki SRPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki rpm -qlp build/SRPMS/pki-*.src.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/SRPMS/pki-*.src.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki SRPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-acme RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-acme-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-acme-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-acme RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-base RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-base-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-base-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-base RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-ca RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-ca-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-ca-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-ca RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-est RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-est-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-est-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-est RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-java RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-java-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-java-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-java RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-javadoc RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-javadoc-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-javadoc-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-javadoc RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-kra RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-kra-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-kra-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-kra RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-ocsp RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-ocsp-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-ocsp-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-ocsp RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-server RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-server-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-server-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-server RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-tests RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-tests-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-tests-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-tests RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-theme RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-theme-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-theme-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-theme RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-tks RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-tks-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-tks-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-tks RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-tools RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-tools-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-tools-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-tools RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-tools-debuginfo RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-tools-debuginfo-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-tools-debuginfo-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-tools-debuginfo RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check dogtag-pki-tps RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/dogtag-pki-tps-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/dogtag-pki-tps-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check dogtag-pki-tps RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check pki-debugsource RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/pki-debugsource-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/pki-debugsource-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-debugsource RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check python3-dogtag-pki RPM"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
VERSION=$(cat VERSION)
docker exec pki rpm -qlp build/RPMS/python3-dogtag-pki-$VERSION.*.rpm
docker exec pki rpminspect-fedora \
    -p pki-rpminspect \
    build/RPMS/python3-dogtag-pki-$VERSION.*.rpm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check python3-dogtag-pki RPM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== rpminspect-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== rpminspect-test PASSED ===="
