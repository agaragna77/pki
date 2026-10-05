#!/bin/bash
# Generated TMT port of .github/workflows/ca-admin-user-test.yml
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
    docker rm -f ds pki 2>/dev/null || true
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA groups"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-group-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA groups (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-show caadmin | tee output

echo "adminType" > expected
sed -n 's/^ *Type: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check auth with CA admin password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import CA signing cert
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

# correct password should work
docker exec pki pki -u caadmin -w Secret.123 ca-user-find

# wrong password should not work
docker exec pki pki -u caadmin -w wrong ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "UnauthorizedException: " > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check auth with CA admin password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change CA admin password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-mod --password new caadmin

# original password should no longer work
docker exec pki pki -u caadmin -w Secret.123 ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "UnauthorizedException: " > expected
diff expected stderr

# new password should work
docker exec pki pki -u caadmin -w new ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change CA admin password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change CA admin password with file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo secret > secret.txt
docker exec pki pki-server ca-user-mod --password-file $SHARED/secret.txt caadmin

# password file should work
docker exec pki pki -u caadmin -w secret ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change CA admin password with file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA admin password"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-mod --password "" caadmin

# old password should no longer work
docker exec pki pki -u caadmin -w secret ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "UnauthorizedException: " > expected
diff expected stderr

# blank password should not work
docker exec pki pki -u caadmin -w "" ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "UnauthorizedException: " > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA admin password (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs assigned to CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-cert-find caadmin | tee output

# get admin cert ID
sed -n 's/^ *Cert ID: *\(.*\)$/\1/p' output > cert.id
CERT_ID=$(cat cert.id)
echo "CERT_ID: $CERT_ID"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs assigned to CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check auth with CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import admin cert
docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

# admin cert should work
docker exec pki pki -n caadmin ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check auth with CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unassign certs from CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
echo "CERT_ID: $CERT_ID"

docker exec pki pki-server ca-user-cert-del caadmin "$CERT_ID"

# admin user should have no certs
docker exec pki pki-server ca-user-cert-find caadmin | tee actual
diff /dev/null actual

# admin cert should no longer work
docker exec pki pki -n caadmin ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "UnauthorizedException: " > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unassign certs from CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Reassign certs to CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
echo "CERT_ID: $CERT_ID"

docker exec pki pki nss-cert-export caadmin > caadmin.crt
cat caadmin.crt | docker exec -i pki pki-server ca-user-cert-add caadmin

# new admin cert ID should match the original admin cert ID
docker exec pki pki-server ca-user-cert-find caadmin | tee output
sed -n 's/^ *Cert ID: *\(.*\)$/\1/p' output > actual
diff cert.id actual

# admin cert should work again
docker exec pki pki -n caadmin ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Reassign certs to CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin roles"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-find caadmin | tee output

echo "Administrators" > expected
echo "Certificate Manager Agents" >> expected
echo "Enterprise CA Administrators" >> expected
echo "Enterprise EST Administrators" >> expected
echo "Enterprise KRA Administrators" >> expected
echo "Enterprise OCSP Administrators" >> expected
echo "Enterprise RA Administrators" >> expected
echo "Enterprise TKS Administrators" >> expected
echo "Enterprise TPS Administrators" >> expected
echo "Security Domain Administrators" >> expected

sed -n 's/^ *Role ID: *\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin roles (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA admin role"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-del caadmin Administrators
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA admin role (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Authorization with CA admin cert should not work"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-user-find \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "ForbiddenException: Authorization Error" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Authorization with CA admin cert should not work (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restore CA admin role"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-add caadmin Administrators
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restore CA admin role (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Authorization with CA admin cert should work again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Authorization with CA admin cert should work again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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

step "Check DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-admin-user-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-admin-user-test PASSED ===="
