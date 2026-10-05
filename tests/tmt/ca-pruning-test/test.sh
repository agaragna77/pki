#!/bin/bash
# Generated TMT port of .github/workflows/ca-pruning-test.yml
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

step "Configure server cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 1 minute
VALIDITY_DEFAULT="policyset.serverCertSet.2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=1/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure server cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure user cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 4 minute
VALIDITY_DEFAULT="policyset.userCertSet.2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=4/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure user cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure cert status update task"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure task to run every minute
docker exec pki pki-server ca-config-set ca.certStatusUpdateInterval 60
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure cert status update task (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure pruning job"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure pruning to run manually without retention time
docker exec pki pki-server ca-config-set jobsScheduler.enabled true
docker exec pki pki-server ca-config-set jobsScheduler.job.pruning.enabled true
docker exec pki pki-server ca-config-set jobsScheduler.job.pruning.certRetentionTime 0
docker exec pki pki-server ca-config-set jobsScheduler.job.pruning.certRetentionUnit minute
docker exec pki pki-server ca-config-set jobsScheduler.job.pruning.requestRetentionTime 0
docker exec pki pki-server ca-config-set jobsScheduler.job.pruning.requestRetentionUnit minute
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure pruning job (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart CA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart CA subsystem (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial certs and requests"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 6 requests initially
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "6" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# there should be 6 certs initially
docker exec pki pki ca-cert-find | tee output

echo "6" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial certs and requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request \
    --profile caServerCert \
    cn=server.example.com | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"
echo $REQUEST_ID > server-request-id

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > server-cert-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create incomplete server cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request \
    --profile caServerCert \
    cn=server.example.com | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"
echo $REQUEST_ID > incomplete-server-request-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create incomplete server cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request \
    --profile caUserCert \
    uid=testuser | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"
echo $REQUEST_ID > user-request-id

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > user-cert-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create incomplete user cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request \
    --profile caUserCert \
    uid=testuser | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"
echo $REQUEST_ID > incomplete-user-request-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create incomplete user cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs after enrollments"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 8 certs now
docker exec pki pki ca-cert-find | tee output

echo "8" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# the server cert should exist
CERT_ID=$(cat server-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the server cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual

# the user cert should exist
CERT_ID=$(cat user-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the user cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs after enrollments (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests after enrollments"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 10 requests now
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "10" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# the completed server request should exist
REQUEST_ID=$(cat server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the incomplete server request should exist
REQUEST_ID=$(cat incomplete-server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the completed user request should exist
REQUEST_ID=$(cat user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the incomplete user request should exist
REQUEST_ID=$(cat incomplete-user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests after enrollments (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for server cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for server cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs after server cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should still be 8 certs
docker exec pki pki ca-cert-find | tee output

echo "8" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# the server cert should still exist
CERT_ID=$(cat server-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the server cert should be expired now
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "EXPIRED" > expected
diff expected actual

# the user cert should still exist
CERT_ID=$(cat user-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the user cert should still be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs after server cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests after server cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should still be 10 requests
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "10" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# the completed server request should still exist
REQUEST_ID=$(cat server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the incomplete server request should still exist
REQUEST_ID=$(cat incomplete-server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the completed user request should still exist
REQUEST_ID=$(cat user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the incomplete user request should still exist
REQUEST_ID=$(cat incomplete-user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests after server cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start the first pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-job-start pruning

sleep 30
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start the first pruning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs after the first pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 7 certs now
docker exec pki pki ca-cert-find | tee output

echo "7" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# the expired server cert should be removed
CERT_ID=$(cat server-cert-id)
docker exec pki pki ca-cert-show $CERT_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "CertNotFoundException: Certificate ID $CERT_ID not found" > expected
diff expected stderr

# the user cert should still exist
CERT_ID=$(cat user-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the user cert should still be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs after the first pruning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests after the first pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 7 requests now
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "7" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# the completed server request should be removed
REQUEST_ID=$(cat server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "RequestNotFoundException: Request ID $REQUEST_ID not found" > expected
diff expected stderr

# the incomplete server request should be removed
REQUEST_ID=$(cat incomplete-server-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "RequestNotFoundException: Request ID $REQUEST_ID not found" > expected
diff expected stderr

# the completed user request should still exist
REQUEST_ID=$(cat user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID

# the incomplete user request should be removed
REQUEST_ID=$(cat incomplete-user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "RequestNotFoundException: Request ID $REQUEST_ID not found" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests after the first pruning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for user cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for user cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs after user cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should still be 7 certs
docker exec pki pki ca-cert-find | tee output

echo "7" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# the user cert should still exist
CERT_ID=$(cat user-cert-id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# the user cert should be expired now
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "EXPIRED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs after user cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests after user cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should still be 7 requests
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "7" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# the completed user request should still exist
REQUEST_ID=$(cat user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests after user cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start the second pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-job-start pruning

sleep 30
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start the second pruning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check certs after the second pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 6 certs again
docker exec pki pki ca-cert-find | tee output

echo "6" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# the expired user cert should be removed
CERT_ID=$(cat user-cert-id)
docker exec pki pki ca-cert-show $CERT_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "CertNotFoundException: Certificate ID $CERT_ID not found" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs after the second pruning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests after the second pruning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 6 requests again
docker exec pki pki -n caadmin ca-cert-request-find | tee output

echo "6" > expected
{ grep "Request ID:" output || true; } | wc -l > actual
diff expected actual

# the completed user request should be removed
REQUEST_ID=$(cat user-request-id)
docker exec pki pki ca-cert-request-show $REQUEST_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "RequestNotFoundException: Request ID $REQUEST_ID not found" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests after the second pruning (rc=$_rc)" >&2
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
    echo "==== ca-pruning-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-pruning-test PASSED ===="
