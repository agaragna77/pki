#!/bin/bash
# Generated TMT port of .github/workflows/ca-ssnv1-test.yml
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

step "Create CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_request_id_generator=legacy \
    -D pki_request_number_range_start=1 \
    -D pki_request_number_range_end=10 \
    -D pki_request_number_range_increment=10 \
    -D pki_request_number_range_minimum=5 \
    -D pki_request_number_range_transfer=5 \
    -D pki_cert_id_generator=legacy \
    -D pki_serial_number_range_start=9 \
    -D pki_serial_number_range_end=18 \
    -D pki_serial_number_range_increment=12 \
    -D pki_serial_number_range_minimum=9 \
    -D pki_serial_number_range_transfer=9 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA (rc=$_rc)" >&2
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
seq 9 14 | while read n; do printf "0x%x\n" $n; done > expected

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

# request range should be 1 - 10 decimal (size: 10, remaining: 4)
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

# cert range should be 9 - 18 hex (size: 16, remaining: 10)
cat > expected << EOF
dbs.beginSerialNumber=9
dbs.endSerialNumber=18
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

# SubsystemRangeUpdateCLI.updateRequestNumberRange() reads dbs.endRequestNumber
# as 10 decimal, increments it by 1 to 11 decimal, then stores it as the
# initial request nextRange.
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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# SubsystemRangeUpdateCLI.updateSerialNumberRange() incorrectly reads
# dbs.endSerialNumber as 18 decimal, increments it by 1 to 19 decimal,
# then stores it as the initial cert nextRange.
cat > expected << EOF
nextRange: 19
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# serial number management is disabled so there are no range objects created
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# serial number management is disabled so there are no range objects created
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enable serial number management"
if [[ "$GHA_FAILED" -eq 0 ]]; then
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
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

# request range should be 1 - 10 decimal (size: 10, remaining: 4)
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

# cert range should be 9 - 18 hex (size: 16, remaining: 10)
cat > expected << EOF
dbs.beginSerialNumber=9
dbs.endSerialNumber=18
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

# request nextRange should be incremented by 10 decimal
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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 19
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# new request range should be 11 - 20 decimal (size: 10)
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# there should be no new cert range
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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
seq 9 24 | while read n; do printf "0x%x\n" $n; done > expected

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

# requelst range should be 11 - 20 decimal (size: 10, remaining: 6)
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

# cert range should be 9 - 18 hex (size: 16, remaining: 0)
cat > expected << EOF
dbs.beginSerialNumber=9
dbs.endSerialNumber=18
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 19
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# request range objects should be the same
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# cert range objects should be the same
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
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
seq 9 24 | while read n; do printf "0x%x\n" $n; done > expected

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

# request range should be 11 - 20 decimal (size: 10, remaining: 3)
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

# cert range should be 9 - 18 hex (size: 16, remaining: 0)
cat > expected << EOF
dbs.beginSerialNumber=9
dbs.endSerialNumber=18
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 19
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# request range objects should be the same
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# cert range objects should be the same
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects (rc=$_rc)" >&2
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

# request range should be the same (size: 10, remaining: 3)
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

# cert range should be the same (size: 16, remaining: 0)
cat > expected << EOF
dbs.beginSerialNumber=9
dbs.endSerialNumber=18
dbs.nextBeginSerialNumber=19
dbs.nextEndSerialNumber=2a
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

# request nextRange should be incremented by 10 decimal to 31 decimal
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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRequest should incremented by 12 hex (18 decimal) to 37 decimal
cat > expected << EOF
nextRange: 37
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# new request range should be 21 - 30 decimal (size: 10)
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# new request range is 19 - 36 decimal (size: 18)
# Note: the size should have been consistent (i.e. 16)
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
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
seq 9 37 | while read n; do printf "0x%x\n" $n; done > expected

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

# request range should be 21 - 30 decimal (size: 10, remaining: 0)
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

# cert range is be 19 - 2a hex (size: 18, remaining: 5)
# Note: the size should have been consistent (i.e. 16)
cat > expected << EOF
dbs.beginSerialNumber=19
dbs.endSerialNumber=2a
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 37
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# cert range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
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
seq 9 37 | while read n; do printf "0x%x\n" $n; done > expected

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

# request range should be the same (size: 10, remaining: 0)
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

# cert range should be the same (size: 18, remaining: 5)
cat > expected << EOF
dbs.beginSerialNumber=19
dbs.endSerialNumber=2a
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be the same
cat > expected << EOF
nextRange: 37
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# cert range objects should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
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

# request range should be the same (size: 10, remaining: 0)
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

# cert range should be the same (size: 18, remaining: 5)
cat > expected << EOF
dbs.beginSerialNumber=19
dbs.endSerialNumber=2a
dbs.nextBeginSerialNumber=37
dbs.nextEndSerialNumber=48
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

# request nextRange should be incremented by 10 decimal to 41 decimal
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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be incremented by 12 hex (18 decimal) to 55 decimal
cat > expected << EOF
nextRange: 55
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# new request range should be 31 - 40 decimal (size: 10)
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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# new cert range should be 37 - 54 decimal (size: 18)
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
host: pki.example.com

SecurePort: 8443
beginRange: 37
endRange: 54
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

step "Enroll 10 additional certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
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
    echo "FAIL: Enroll 10 additional certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 40 requests (30 existing + 10 new)
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

# there should be 39 certs (29 existing + 10 new)
# but due to a bug the serial numbers have a gap

# seq 9 47 | while read n; do printf "0x%x\n" $n; done > expected
seq 9 42 | while read n; do printf "0x%x\n" $n; done > expected
seq 55 59 | while read n; do printf "0x%x\n" $n; done >> expected

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

# request range should be 31 - 40 decimal (size: 10, remaining: 0)
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

# cert range should have been 2b - 36 hex (size: 18, remaining: 13)
# but it jumps to 37 - 48 hex
cat > expected << EOF
dbs.beginSerialNumber=37
dbs.endSerialNumber=48
dbs.serialCloneTransferNumber=9
dbs.serialIncrement=12
dbs.serialLowWaterMark=9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

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
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# cert nextRange should be incremented by 12 hex (18 decimal) to 55 decimal
cat > expected << EOF
nextRange: 55
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

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
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# cert range should be the same
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
host: pki.example.com

SecurePort: 8443
beginRange: 37
endRange: 54
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

step "Switch to legacy2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server stop
docker exec pki pki-server ca-id-generator-update -v --type legacy2 request
docker exec pki pki-server ca-id-generator-update -v --type legacy2 cert
docker exec pki pki-server start --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Switch to legacy2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output
# request range should be the same
cat > expected << EOF
dbs.beginRequestNumber=31
dbs.endRequestNumber=40
dbs.nextBeginRequestNumber=41
dbs.nextEndRequestNumber=50
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

cat > expected << EOF
dbs.beginSerialNumber=0x37
dbs.endSerialNumber=0x54
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

step "Check the radix configured for the new generator"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-show dbs.request.id.radix | tee output
docker exec pki pki-server ca-config-show dbs.cert.id.radix | tee -a output

cat > expected <<EOF
10
16
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check the radix configured for the new generator (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ranges entry is configured in a new tree"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-show dbs.serialRangeDN | tee output
docker exec pki pki-server ca-config-show dbs.requestRangeDN | tee -a output

cat > expected <<EOF
ou=certificateRepository,ou=ranges_v2
ou=requests,ou=ranges_v2
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ranges entry is configured in a new tree (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# new request range should be 31 - 40 decimal (total: 10)
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
    echo "FAIL: Check request range objects for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

# new request range should be 31 - 40 decimal (total: 10)
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

SecurePort: 8443
beginRange: 41
endRange: 50
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

# request nextRange should be incremented by 10 decimal to 41 decimal
cat > expected << EOF
nextRange: 41
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

# request nextRange should be incremented by 10 decimal to 41 decimal
cat > expected << EOF
nextRange: 51
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# new cert range should be the same but converted to decimal
# first range move from 19-36 (hex) to 25-54 (dec)
# second range move from 37-54 (hex) to 55-84 (dec)
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
host: pki.example.com

SecurePort: 8443
beginRange: 37
endRange: 54
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

# new cert range should be the same but converted to decimal
# first range move from 19-36 (hex) to 25-54 (dec)
# second range move from 37-54 (hex) to 55-84 (dec)
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 54
host: pki.example.com

SecurePort: 8443
beginRange: 55
endRange: 84
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# next range should remain the same
cat > expected << EOF
nextRange: 55
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# next range should be endRange + 1
cat > expected << EOF
nextRange: 85
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll additional certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
# Enroll until request range exhausted
for i in $(seq 1 9); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
# Enroll until request range exhausted
for i in $(seq 1 10); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
# Enroll until request range exhausted
for i in $(seq 1 10); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
# Enroll until request range exhausted
for i in $(seq 1 10); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
# Enroll until request range exhausted
for i in $(seq 1 10); do
    docker exec pki pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec pki openssl x509 -in testuser.crt -serial -noout
done
docker exec pki pki -n caadmin ca-job-start serialNumberUpdate
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll additional certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh pki | tee output

cat > expected << EOF
dbs.beginRequestNumber=81
dbs.endRequestNumber=90
dbs.nextBeginRequestNumber=91
dbs.nextEndRequestNumber=100
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

cat > expected << EOF
dbs.beginSerialNumber=0x67
dbs.endSerialNumber=0x78
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

step "Check request range objects for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh ds | tee output

# new request range should be 31 - 40 decimal (total: 10)
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
    echo "FAIL: Check request range objects for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 ds | tee output

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

SecurePort: 8443
beginRange: 41
endRange: 50
host: pki.example.com

SecurePort: 8443
beginRange: 51
endRange: 60
host: pki.example.com

SecurePort: 8443
beginRange: 61
endRange: 70
host: pki.example.com

SecurePort: 8443
beginRange: 71
endRange: 80
host: pki.example.com

SecurePort: 8443
beginRange: 81
endRange: 90
host: pki.example.com

SecurePort: 8443
beginRange: 91
endRange: 100
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range objects for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh ds | tee output

cat > expected << EOF
nextRange: 41
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request next range for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-next-range.sh -t legacy2 ds | tee output

cat > expected << EOF
nextRange: 101
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request next range for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh ds | tee output

# new cert range should be the same but converted to decimal
# first range move from 19-36 (hex) to 25-54 (dec)
# second range move from 37-54 (hex) to 55-84 (dec)
cat > expected << EOF
SecurePort: 8443
beginRange: 19
endRange: 36
host: pki.example.com

SecurePort: 8443
beginRange: 37
endRange: 54
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range objects for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 ds | tee output

cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 54
host: pki.example.com

SecurePort: 8443
beginRange: 55
endRange: 84
host: pki.example.com

SecurePort: 8443
beginRange: 85
endRange: 102
host: pki.example.com

SecurePort: 8443
beginRange: 103
endRange: 120
host: pki.example.com

EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range objects for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range for SSNv1"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh ds | tee output

# next range should remain the same
cat > expected << EOF
nextRange: 55
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range for SSNv1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert next range for SSNv2"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-next-range.sh -t legacy2 ds | tee output

# next range should be endRange + 1
cat > expected << EOF
nextRange: 121
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert next range for SSNv2 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-request-find | tee output

sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 40 requests (30 existing + 10 new)
seq 1 89 > expected

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

# there should be 39 certs (29 existing + 10 new)
# but due to a bug the serial numbers have a gap

# seq 1 39 | while read n; do printf "0x%x\n" $n; done > expected
seq 9 42 | while read n; do printf "0x%x\n" $n; done > expected
seq 55 108 | while read n; do printf "0x%x\n" $n; done >> expected

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

step "Check requests"
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
    echo "FAIL: Check requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > list

# there should be 39 certs with sequential serial numbers
# but due to a bug the serial numbers have a gap

# seq 9 47 | while read n; do printf "0x%x\n" $n; done > expected
seq 9 42 | while read n; do printf "0x%x\n" $n; done > expected
seq 55 59 | while read n; do printf "0x%x\n" $n; done >> expected

head -n 39 list > actual
diff expected actual

# there should be one cert with random serial number (longer than 4 chars)

SERIAL_NUMBER=$(tail -n 1 list)
[ ${#SERIAL_NUMBER} -gt 4 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
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
    echo "==== ca-ssnv1-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-ssnv1-test PASSED ===="
