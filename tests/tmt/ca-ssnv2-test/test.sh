#!/bin/bash
# Generated TMT port of .github/workflows/ca-ssnv2-test.yml
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

step "Create CA with unsupported range format"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > expected <<EOF
Loading deployment configuration from /usr/share/pki/server/examples/installation/ca.cfg.
Installing CA into /var/lib/pki/pki-tomcat.

Installation failed: pki_serial_number_range_start must start with 0x

EOF

docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_request_id_generator=legacy2 \
    -D pki_request_number_range_start=1 \
    -D pki_request_number_range_end=10 \
    -D pki_request_number_range_increment=10 \
    -D pki_request_number_range_minimum=5 \
    -D pki_request_number_range_transfer=5 \
    -D pki_cert_id_generator=legacy2 \
    -D pki_serial_number_range_start=9 \
    -D pki_serial_number_range_end=18 \
    -D pki_serial_number_range_increment=12 \
    -D pki_serial_number_range_minimum=9 \
    -D pki_serial_number_range_transfer=9 \
    -v | tee actual || true

    diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA with unsupported range format (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Cleanup CA installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA --remove-conf --remove-logs --force
docker exec pki rm -rf /root/.dogtag/pki-tomcat
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Cleanup CA installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_request_id_generator=legacy2 \
    -D pki_request_number_range_start=1 \
    -D pki_request_number_range_end=10 \
    -D pki_request_number_range_increment=10 \
    -D pki_request_number_range_minimum=5 \
    -D pki_request_number_range_transfer=5 \
    -D pki_cert_id_generator=legacy2 \
    -D pki_serial_number_range_start=0x9 \
    -D pki_serial_number_range_end=0x18 \
    -D pki_serial_number_range_increment=0x12 \
    -D pki_serial_number_range_minimum=0x9 \
    -D pki_serial_number_range_transfer=0x9 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 6 requests
seq 1 6 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 6 certs
printf "0x%x\n" {9..14} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 1 - 10 (size: 10, remaining: 4)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x9 - 0x18 (size: 0x10, remaining: 0xa)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0x18
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be dbs.endRequestNumber + 1 = 11
cat > expected << EOF
nextRange: 11
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be dbs.endSerialNumber + 1 = 0x19 or 25
cat > expected << EOF
nextRange: 25
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enable serial number management"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-set dbs.enableSerialManagement true

# disable serial number update background task
docker exec pki pki-server ca-config-set ca.serialNumberUpdateInterval 0

# enable serial number update manual job
docker exec pki pki-server ca-config-set jobsScheduler.enabled true
docker exec pki pki-server ca-config-set jobsScheduler.job.serialNumberUpdate.enabled true

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable serial number management (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 1 - 10 (size: 10, remaining: 4)
# new range should be 11 - 20 (size: 10, remaining: 10)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.nextBeginRequestNumber=11
dbs.nextEndRequestNumber=20
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x9 - 0x18 (size: 0x10, remaining: 0xa)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0x18
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# new range should be 11 - 20 (size: 10)
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# nextRange should be endRange + 1 = 21
cat > expected << EOF
nextRange: 21
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# nextRange should be the same
cat > expected << EOF
nextRange: 25
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 10 certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "uid=testuser" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser.csr

for i in $(seq 1 10); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 10 certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 16 requests
seq 1 16 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output

sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 16 certs
printf "0x%x\n" {9..24} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 11 - 20 (size: 10, remaining: 4)
cat > expected << EOF
dbs.beginRequestNumber=11
dbs.endRequestNumber=20
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x9 - 0x18 (size: 0x10, remaining: 0x0)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0x18
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# nextRange should be the same
cat > expected << EOF
nextRange: 21
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# nextRange should be the same
cat > expected << EOF
nextRange: 25
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert when cert range is exhausted"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# TODO: fix missing request ID and typo
cat > expected << EOF
PKIException: Server Internal Error: Request 17 was completed with errors.
CA has exhausted all available serial numbers
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert when cert range is exhausted (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 17 requests
seq 1 17 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output

sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 16 certs
printf "0x%x\n" {9..24} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 11 - 20 (size: 10, remaining: 3)
cat > expected << EOF
dbs.beginRequestNumber=11
dbs.endRequestNumber=20
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x9 - 0x18 (size: 0x10, remaining: 0x0)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0x18
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# there should be no new range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be the same
cat > expected << EOF
nextRange: 21
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 25
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Allocate new ranges"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Allocate new ranges (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 11 - 20 (size: 10, remaining: 3)
# new range should be 21 - 30 (size: 10, remaining: 10)
cat > expected << EOF
dbs.beginRequestNumber=11
dbs.endRequestNumber=20
dbs.nextBeginRequestNumber=21
dbs.nextEndRequestNumber=30
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x9 - 0x18 (size: 0x10, remaining: 0x0)
# new range should be 0x19 - 0x2a (size: 0x12, remaining: 0x12)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0x18
dbs.nextBeginSerialNumber=0x19
dbs.nextEndSerialNumber=0x2a
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# new request range should be 21 - 30 (size: 10)
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# new cert range should be 0x19 - 0x2a or 25 - 42 (size: 0x12)
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be incremented by 10 to 31
cat > expected << EOF
nextRange: 31
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRequest should incremented by 0x12 to 0x2b or 43
cat > expected << EOF
nextRange: 43
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 13 additional certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
for i in $(seq 1 13); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 13 additional certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 30 requests (17 existing + 13 new)
seq 1 30 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output

sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 29 certs (16 existing + 13 new)
printf "0x%x\n" {9..37} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 21 - 30 (size: 10, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=21
dbs.endRequestNumber=30
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x19 - 0x2a (size: 0x12, remaining: 0x5)
cat > expected << EOF
dbs.beginSerialNumber=0x19
dbs.endSerialNumber=0x2a
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# request range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# cert range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be the same
cat > expected << EOF
nextRange: 31
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 43
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert when request range is exhausted"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
PKIException: Unable to create enrollment request: Unable to create enrollment request: All serial numbers are used. The max serial number is 30
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert when request range is exhausted (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# requests should be the same
seq 1 30 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output

sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# certs should be the same
printf "0x%x\n" {9..37} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 21 - 30 (size: 10, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=21
dbs.endRequestNumber=30
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x19 - 0x2a (size: 0x12, remaining: 0x5)
cat > expected << EOF
dbs.beginSerialNumber=0x19
dbs.endSerialNumber=0x2a
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# request range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# cert range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be the same
cat > expected << EOF
nextRange: 31
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 43
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Allocate new ranges again"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Allocate new ranges again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# current range should be 21 - 30 (size: 10, remaining: 0)
# next range should be 31 - 40 (size: 10, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=21
dbs.endRequestNumber=30
dbs.nextBeginRequestNumber=31
dbs.nextEndRequestNumber=40
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x19 - 0x2a (size: 0x12, remaining: 0x5)
# next range should be 0x2b - 0x3c (size: 0x12, remaining: 0x12)
cat > expected << EOF
dbs.beginSerialNumber=0x19
dbs.endSerialNumber=0x2a
dbs.nextBeginSerialNumber=0x2b
dbs.nextEndSerialNumber=0x3c
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# new range should be 31 - 40 (size: 10)
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: pki.example.com

SecurePort: 8443
beginRange: 31
endRange: 40
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# new range should be 0x2b - 0x3c or 43 - 60 (size: 0x12)
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: pki.example.com

SecurePort: 8443
beginRange: 43
endRange: 60
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be incremented by 10 to 41
cat > expected << EOF
nextRange: 41
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be incremented by 0x12 to 0x47 or 61
cat > expected << EOF
nextRange: 61
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 7 additional certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
for i in $(seq 1 7); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 7 additional certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 37 requests (30 existing + 7 new)
seq 1 37 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output

sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 36 certs (29 existing + 7 new)
printf "0x%x\n" {9..44} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# request range should be 31 - 40 (size: 10, remaining: 3)
cat > expected << EOF
dbs.beginRequestNumber=31
dbs.endRequestNumber=40
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh pki | tee output

# current range should be 0x2b - 0x3c (size: 0x12, remaining: 0x10)
cat > expected << EOF
dbs.beginSerialNumber=0x2b
dbs.endSerialNumber=0x3c
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# request range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: pki.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: pki.example.com

SecurePort: 8443
beginRange: 31
endRange: 40
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# cert range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: pki.example.com

SecurePort: 8443
beginRange: 43
endRange: 60
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be the same
cat > expected << EOF
nextRange: 41
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 61
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Create a request record with the next ID"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# get the latest request record
docker exec ds ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=37,ou=ca,ou=requests,dc=ca,dc=pki,dc=example,dc=com" \
    -s base \
    -o ldif_wrap=no \
    -LLL | tee request.ldif

# replace the ID with the next ID
sed -i \
    -e "s/^dn: cn=37,/dn: cn=38,/" \
    -e "s/^requestId: 0237/requestId: 0238/" \
    -e "s/^extdata-requestid: 37/extdata-requestid: 38/" \
    -e "s/^cn: 37/cn: 38/" \
    request.ldif

# add the updated request record
docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -f $SHARED/request.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create a request record with the next ID (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert with a conflicting request record ID"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# create a new CSR
docker exec pki pki \
    nss-cert-request \
    --subject "uid=testuser2" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser2.csr

# the CLI should complete successfully
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser2.csr \
    --output-file testuser2.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert with a conflicting request record ID (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request records"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 39 request records (37 existing + 1 conflicting + 1 new)
# but currently the CA reuses the conflicting request record instead of
# creating a new one
seq 1 38 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request records (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check conflicting request record"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ds ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=38,ou=ca,ou=requests,dc=ca,dc=pki,dc=example,dc=com" \
    -s base \
    -o ldif_wrap=no \
    -LLL | tee request-after.ldif

# the conflicting request record should not change
# but currently it is updated to store the new CSR
diff request.ldif request-after.ldif || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conflicting request record (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert records"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 37 cert records (36 existing + 1 new)
printf "0x%x\n" {9..45} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert records (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Create a cert with the next serial number"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ds ldapsearch \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=45,ou=certificateRepository,ou=ca,dc=ca,dc=pki,dc=example,dc=com" \
    -s base \
    -o ldif_wrap=no \
    -LLL | tee cert.ldif

sed -i \
    -e "s/^dn: cn=45,/dn: cn=46,/" \
    -e "s/^serialno: 0245/serialno: 0246/" \
    -e "s/^cn: 45/cn: 46/" \
    cert.ldif

docker exec ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -f $SHARED/cert.ldif
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create a cert with the next serial number (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert with a conflicting serial number"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# the CLI should complete successfully, but currently it's failing
cat > expected << EOF
PKIException: Server Internal Error: Unable to add certificate record: Record already exists
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert with a conflicting serial number (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 39 requests (38 existing + 1 new)
seq 1 39 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 39 requests (37 existing + 1 conflicting + 1 new)
# but currently there is no new cert issued
printf "0x%x\n" {9..46} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert after conflicts"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert after conflicts (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 40 requests (39 existing + 1 new)
seq 1 40 > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 39 certs (38 existing + 1 new)
printf "0x%x\n" {9..47} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Switch to RSNv3"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# switch cert request ID generator to RSNv3
docker exec pki pki-server ca-config-unset dbs.beginRequestNumber
docker exec pki pki-server ca-config-unset dbs.endRequestNumber
docker exec pki pki-server ca-config-unset dbs.requestIncrement
docker exec pki pki-server ca-config-unset dbs.requestLowWaterMark
docker exec pki pki-server ca-config-unset dbs.requestCloneTransferNumber
docker exec pki pki-server ca-config-unset dbs.requestRangeDN

docker exec pki pki-server ca-config-set dbs.request.id.generator random

# switch cert ID generator to RSNv3
docker exec pki pki-server ca-config-unset dbs.beginSerialNumber
docker exec pki pki-server ca-config-unset dbs.endSerialNumber
docker exec pki pki-server ca-config-unset dbs.serialIncrement
docker exec pki pki-server ca-config-unset dbs.serialLowWaterMark
docker exec pki pki-server ca-config-unset dbs.serialCloneTransferNumber
docker exec pki pki-server ca-config-unset dbs.serialRangeDN

docker exec pki pki-server ca-config-set dbs.cert.id.generator random

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Switch to RSNv3 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert with RSNv3"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt

docker exec pki openssl x509 -in testuser.crt -serial -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert with RSNv3 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find all cert requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > list

# there should be 40 requests with sequential request ID
seq 1 40 > expected
head -n 40 list > actual
diff expected actual

# there should be one request with random request ID (longer than 2 chars)
REQUEST_ID=$(tail -n 1 list)
[ ${#REQUEST_ID} -gt 2 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find all cert requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find cert requests page 1 with REST API v1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    --api v1 \
    ca-cert-request-find \
    --start 0 \
    --size 25 \
    | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# in REST API v1 the --start determines the starting request ID so
# it should return the first 25 entries starting from request ID 0
printf "0x%x\n" {1..25} > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find cert requests page 1 with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find cert requests page 2 with REST API v1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    --api v1 \
    ca-cert-request-find \
    --start 25 \
    --size 25 \
    | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > list

# in REST API v1 the --start is used as the starting request ID so it
# should return the remaining 17 entries starting from request ID 25
echo "17" > expected
cat list | wc -l > actual
diff expected actual

# the first 16 cert requests should have request IDs from 25 to 40
printf "0x%x\n" {25..40} > expected
head -n 16 list > actual
diff expected actual

# the last cert request should have random request ID (longer than 2 chars)
SERIAL_NUMBER=$(tail -n 1 list)
[ ${#SERIAL_NUMBER} -gt 2 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find cert requests page 2 with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find cert requests page 1 with REST API v2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    --api v2 \
    ca-cert-request-find \
    --start 0 \
    --size 25 \
    | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# in REST API v2 the --start is used as the starting index
# so it should return the first 25 entries
printf "0x%x\n" {1..25} > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find cert requests page 1 with REST API v2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find cert requests page 2 with REST API v2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    --api v2 \
    ca-cert-request-find \
    --start 25 \
    --size 25 \
    | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > list

# in REST API v2 the --start is used as the starting index
# so it should return the remaining 16 entries
echo "16" > expected
cat list | wc -l > actual
diff expected actual

# the first 15 cert requests should have request IDs from 26 to 40
printf "0x%x\n" {26..40} > expected
head -n 15 list > actual
diff expected actual

# the last cert request should have random request ID (longer than 2 chars)
SERIAL_NUMBER=$(tail -n 1 list)
[ ${#SERIAL_NUMBER} -gt 2 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find cert requests page 2 with REST API v2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find all certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > list

# there should be 39 certs with sequential serial numbers
printf "0x%x\n" {9..47} > expected
head -n 39 list > actual
diff expected actual

# there should be one cert with random serial number (longer than 4 chars)
SERIAL_NUMBER=$(tail -n 1 list)
[ ${#SERIAL_NUMBER} -gt 4 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find all certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find certs page 1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find --start 0 --size 25 | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# it should return the first 25 certs with serial numbers from 9 to 33
printf "0x%x\n" {9..33} > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find certs page 1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Find certs page 2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find --start 25 --size 25 | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > list

# it should return the remaining 15 certs
echo "15" > expected
cat list | wc -l > actual
diff expected actual

# the first 14 certs should have serial numbers from 34 to 47
printf "0x%x\n" {34..47} > expected
head -n 14 list > actual
diff expected actual

# the last cert should have random serial number (longer than 4 chars)
SERIAL_NUMBER=$(tail -n 1 list)
[ ${#SERIAL_NUMBER} -gt 4 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Find certs page 2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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

step "Check PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log (rc=$_rc)" >&2
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
    echo "==== ca-ssnv2-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-ssnv2-test PASSED ===="
