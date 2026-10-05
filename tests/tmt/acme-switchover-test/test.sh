#!/bin/bash
# Generated TMT port of .github/workflows/acme-switchover-test.yml
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
    docker rm -f client ds pki 2>/dev/null || true
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

step "Retrieve ACME images"
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
    echo "FAIL: Retrieve ACME images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load ACME images"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker load from cache — images built locally by prepare
echo "Images already available (built by TMT prepare)"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Load ACME images (rc=$_rc)" >&2
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
    --network-alias=server1.example.com \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in PKI container"
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
    echo "FAIL: Install CA in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install ACME in PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server acme-create
docker exec pki pki-server acme-database-mod \
    --type ds \
    -D url=ldap://ds.example.com:3389 \
    -D bindPassword=Secret.123
docker exec pki pki-server acme-issuer-mod \
    --type pki \
    -D url=https://pki.example.com:8443 \
    -D password=Secret.123
docker exec pki pki-server acme-realm-mod \
    --type ds \
    -D url=ldap://ds.example.com:3389 \
    -D bindPassword=Secret.123
docker exec pki bash -c "echo baseURL=http://server1.example.com:8080/acme >> /var/lib/pki/pki-tomcat/conf/acme/engine.conf"
docker exec pki pki-server acme-deploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install ACME in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize ACME database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server acme-database-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize ACME realm"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server acme-realm-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME realm (rc=$_rc)" >&2
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
    --network-alias=client1.example.com \
    --network-alias=client2.example.com \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install dependencies in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y certbot jq
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify ACME directory before switchover"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo http://server1.example.com:8080/acme/new-nonce > expected
docker exec client bash -c "curl -s -k http://pki.example.com:8080/acme/directory | jq -r '.newNonce' > ${SHARED}/actual"
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify ACME directory before switchover (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify registration and enrollment before switchover"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://pki.example.com:8080/acme/directory \
    --email user1@example.com \
    --agree-tos \
    --non-interactive
docker exec client certbot certonly \
    --server http://pki.example.com:8080/acme/directory \
    -d client1.example.com \
    --key-type rsa \
    --standalone \
    --non-interactive
docker exec client openssl x509 -text -noout -in /etc/letsencrypt/live/client1.example.com/fullchain.pem
docker exec client certbot certonly \
    --server http://pki.example.com:8080/acme/directory \
    -d client2.example.com \
    --key-type rsa \
    --standalone \
    --non-interactive
docker exec client openssl x509 -text -noout -in /etc/letsencrypt/live/client2.example.com/fullchain.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify registration and enrollment before switchover (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Simulate ACME server switchover by replacing the baseURL parameter"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server acme-undeploy --wait
docker network disconnect example pki
docker exec pki sed -i "s/server1.example.com/server2.example.com/g" /var/lib/pki/pki-tomcat/conf/acme/engine.conf
docker network connect example pki --alias pki.example.com --alias server2.example.com
docker exec pki pki-server acme-deploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Simulate ACME server switchover by replacing the baseURL parameter (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify ACME directory after switchover"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo http://server2.example.com:8080/acme/new-nonce > expected
docker exec client bash -c "curl -s -k http://pki.example.com:8080/acme/directory | jq -r '.newNonce' > ${SHARED}/actual"
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify ACME directory after switchover (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify renewal, revocation, account update and deactivation after switchover"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot renew \
    --server http://pki.example.com:8080/acme/directory \
    --cert-name client1.example.com \
    --force-renewal \
    --no-random-sleep-on-renew \
    --non-interactive
docker exec client openssl x509 -text -noout -in /etc/letsencrypt/live/client1.example.com/fullchain.pem
docker exec client certbot revoke \
    --server http://pki.example.com:8080/acme/directory \
    --cert-name client2.example.com \
    --non-interactive
docker exec client certbot update_account \
    --server http://pki.example.com:8080/acme/directory \
    --email user2@example.com \
    --non-interactive
docker exec client certbot unregister \
    --server http://pki.example.com:8080/acme/directory \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify renewal, revocation, account update and deactivation after switchover (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME from PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server acme-undeploy --wait
docker exec pki pki-server acme-remove
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME from PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from PKI container (rc=$_rc)" >&2
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

step "Check ACME debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/acme -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certbot log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec client cat /var/log/letsencrypt/letsencrypt.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certbot log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== acme-switchover-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-switchover-test PASSED ===="
