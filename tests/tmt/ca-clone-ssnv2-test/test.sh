#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-ssnv2-test.yml
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
    docker rm -f primary primaryds secondary secondaryds 2>/dev/null || true
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

step "Set up primary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=primaryds.example.com \
    --network=example \
    --network-alias=primaryds.example.com \
    --password=Secret.123 \
    primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primary.example.com \
    --network=example \
    --network-alias=primary.example.com \
    primary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
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
    echo "FAIL: Create primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable serial number management in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-config-set dbs.enableSerialManagement true

# disable serial number update background task
docker exec primary pki-server ca-config-set ca.serialNumberUpdateInterval 0

# enable serial number update manual job
docker exec primary pki-server ca-config-set jobsScheduler.enabled true
docker exec primary pki-server ca-config-set jobsScheduler.job.serialNumberUpdate.enabled true

# restart primary CA
docker exec primary pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable serial number management in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install admin cert in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec primary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install admin cert in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki-server ca-cert-request-find | tee output
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
docker exec primary pki-server ca-cert-find | tee output
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

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 1 - 10 (size: 10, remaining: 4)
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
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

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
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 primaryds | tee output

# new range should be 11 - 20 (size: 10)
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: primary.example.com

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
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 primaryds | tee output

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
tests/ca/bin/ca-request-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be endRange + 1 = 11
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
tests/ca/bin/ca-cert-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be dbs.endSerialNumber + 1 = 0x19 or 25
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

step "Set up secondary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=secondaryds.example.com \
    --network=example \
    --network-alias=secondaryds.example.com \
    --password=Secret.123 \
    secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondary.example.com \
    --network=example \
    --network-alias=secondary.example.com \
    secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-clone-prepare \
    --pkcs12-file $SHARED/ca-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/ca-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -D pki_request_id_generator=legacy2 \
    -D pki_request_number_range_increment=10 \
    -D pki_request_number_range_minimum=5 \
    -D pki_request_number_range_transfer=5 \
    -D pki_cert_id_generator=legacy2 \
    -D pki_serial_number_range_increment=0x12 \
    -D pki_serial_number_range_minimum=0x9 \
    -D pki_serial_number_range_transfer=0x9 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable serial number management in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-config-set dbs.enableSerialManagement true

# disable serial number update background task
docker exec secondary pki-server ca-config-set ca.serialNumberUpdateInterval 0

# enable serial number update manual job
docker exec secondary pki-server ca-config-set jobsScheduler.enabled true
docker exec secondary pki-server ca-config-set jobsScheduler.job.serialNumberUpdate.enabled true

# restart secondary CA
docker exec secondary pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable serial number management in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install admin cert in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED/ca_admin_cert.p12

docker exec secondary pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install admin cert in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 7 requests
seq 1 7 > expected

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
docker exec secondary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 7 certs
printf "0x%x\n" {9..15} > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 1 - 10 (size: 10, remaining: 3)
# next range should be 11 - 15 (size: 5, remaining: 5)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.nextBeginRequestNumber=11
dbs.nextEndRequestNumber=15
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh secondary | tee output

# current range should be 16 - 20 (size: 5, remaining: 5)
# it was taken from the primary CA's allocated range
# NOTE: should it be taken from the primary CA's current range instead?
cat > expected << EOF
dbs.beginRequestNumber=16
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
    echo "FAIL: Check request range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

# current range should be reduced into 0x9 - 0xf (size: 0x7, remaining: 0x0)
# part of it was transferred to the secondary CA
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0xf
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh secondary | tee output

# current range should be 0x10 - 0x18 (size: 0x9, remaining: 0x9)
# it was taken from the primary CA's current range
cat > expected << EOF
dbs.beginSerialNumber=0x10
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
    echo "FAIL: Check cert range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 secondaryds | tee output

# there should be no new range
# NOTE: there's no indication that part of is has
# been transfered to the secondary CA
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: primary.example.com

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
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 secondaryds | tee output

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
tests/ca/bin/ca-request-next-range.sh -t legacy2 secondaryds | tee output

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
tests/ca/bin/ca-cert-next-range.sh -t legacy2 secondaryds | tee output

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

step "Enroll 5 certs in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki \
    nss-cert-request \
    --subject "uid=testuser" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser.csr

for i in $(seq 1 5); do
    docker exec secondary pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec secondary openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 5 certs in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 12 requests
seq 1 7 > expected
seq 16 20 >> expected

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
docker exec primary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 12 certs
printf "0x%x\n" {9..15} > expected    # primary CA
printf "0x%x\n" {16..20} >> expected  # secondary CA

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 1 - 10 (size: 10, remaining: 3)
# next range should be 11 - 15 (size: 5, remaining: 5)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.nextBeginRequestNumber=11
dbs.nextEndRequestNumber=15
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh secondary | tee output

# current range should be 16 - 20 (size: 5, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=16
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
    echo "FAIL: Check request range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

# current range should be 0x9 - 0xf (size: 0x7, remaining: 0x0)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0xf
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh secondary | tee output

# current range should be 0x10 - 0x18 (size: 0x9, remaining: 0x4)
cat > expected << EOF
dbs.beginSerialNumber=0x10
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
    echo "FAIL: Check cert range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 primaryds | tee output

# there should be no new range
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: primary.example.com

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
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 primaryds | tee output

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
tests/ca/bin/ca-request-next-range.sh -t legacy2 primaryds | tee output

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
tests/ca/bin/ca-cert-next-range.sh -t legacy2 primaryds | tee output

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

step "Enroll a cert when cert range is exhausted in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki \
    nss-cert-request \
    --subject "uid=testuser" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser.csr

docker exec primary pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# TODO: fix missing request ID and typo
cat > expected << EOF
PKIException: Server Internal Error: Request 8 was completed with errors.
CA has exhausted all available serial numbers
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert when cert range is exhausted in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll a cert when request range is exhausted in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
PKIException: Unable to create enrollment request: Unable to create enrollment request: All serial numbers are used. The max serial number is 20
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll a cert when request range is exhausted in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 13 requests
seq 1 7 > expected     # primary CA
seq 16 20 >> expected  # secondary CA
echo 8 >> expected     # primary CA

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
docker exec primary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 12 certs
printf "0x%x\n" {9..15} > expected    # primary CA
printf "0x%x\n" {16..20} >> expected  # secondary CA

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 1 - 10 (size: 10, remaining: 2)
# next range should be 11 - 15 (size: 5, remaining: 5)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.nextBeginRequestNumber=11
dbs.nextEndRequestNumber=15
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh secondary | tee output

# current range should be 16 - 20 (size: 5, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=16
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
    echo "FAIL: Check request range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

# current range should be 0x9 - 0xf (size: 0x7, remaining: 0x0)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0xf
dbs.serialCloneTransferNumber=0x9
dbs.serialIncrement=0x12
dbs.serialLowWaterMark=0x9
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh secondary | tee output

# current range should be 0x10 - 0x18 (size: 0x9, remaining: 0x4)
cat > expected << EOF
dbs.beginSerialNumber=0x10
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
    echo "FAIL: Check cert range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Allocate new ranges"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki \
    -n caadmin \
    ca-job-start \
    serialNumberUpdate

docker exec secondary pki \
    -n caadmin \
    ca-job-start \
    serialNumberUpdate

# wait for DS replication
sleep 5
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Allocate new ranges (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 1 - 10 (size: 10, remaining: 2)
# next range should be 11 - 15 (size: 5, remaining: 5)
cat > expected << EOF
dbs.beginRequestNumber=1
dbs.endRequestNumber=10
dbs.nextBeginRequestNumber=11
dbs.nextEndRequestNumber=15
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh secondary | tee output

# current range should be 16 - 20 (size: 5, remaining: 0)
# next range should be 21 - 30 (size: 10, remaining: 10)
cat > expected << EOF
dbs.beginRequestNumber=16
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
    echo "FAIL: Check request range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

# current range should be 0x9 - 0xf (size: 0x7, remaining: 0x0)
# next range should be 0x19 - 0x2a (size: 0x12, remaining: 0x12)
cat > expected << EOF
dbs.beginSerialNumber=0x9
dbs.endSerialNumber=0xf
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
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh secondary | tee output

# current range should be 0x10 - 0x18 (size: 0x9, remaining: 0x4)
# next range should be 0x2b - 0x3c (size: 0x12, remaining: 0x12)
cat > expected << EOF
dbs.beginSerialNumber=0x10
dbs.endSerialNumber=0x18
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
    echo "FAIL: Check cert range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 primaryds | tee output

# new range should be 21 - 30 (size: 10)
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: primary.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: secondary.example.com

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
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 primaryds | tee output

# new range should be 0x2b - 0x3c or 43 - 60 (size: 0x12)
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: primary.example.com

SecurePort: 8443
beginRange: 43
endRange: 60
host: secondary.example.com

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
tests/ca/bin/ca-request-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be endRange + 1 = 31
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
tests/ca/bin/ca-cert-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be endRange + 1 = 61 or 0x3d
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

step "Enroll 7 certs in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
for i in $(seq 1 7); do
    docker exec primary pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec primary openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 7 certs in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 10 certs in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
for i in $(seq 1 10); do
    docker exec secondary pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec secondary openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 10 certs in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 30 requests
seq 1 7 > expected     # primary CA
seq 16 20 >> expected  # secondary CA
seq 8 15 >> expected   # primary CA
seq 21 30 >> expected  # secondary CA

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
docker exec primary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 29 certs. since the certs were issued by
# different CAs with different ranges, it's normal to have
# a gap temporarily, and the gap should disappear when the
# ranges are exhausted.

printf "0x%x\n" {9..15} > expected    # primary CA
printf "0x%x\n" {16..24} >> expected  # secondary CA
printf "0x%x\n" {25..31} >> expected  # primary CA
printf "0x%x\n" {43..48} >> expected  # secondary CA

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh primary | tee output

# current range should be 11 - 15 (size: 5, remaining: 0)
cat > expected << EOF
dbs.beginRequestNumber=11
dbs.endRequestNumber=15
dbs.requestCloneTransferNumber=5
dbs.requestIncrement=10
dbs.requestLowWaterMark=5
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check request range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-config.sh secondary | tee output

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
    echo "FAIL: Check request range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh primary | tee output

# current range should be 0x19 - 0x2a (size: 0x12, remaining: 0xb)
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
    echo "FAIL: Check cert range config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check cert range config in secondary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-cert-range-config.sh secondary | tee output

# current range should be 0x2b - 0x3c (size: 0x12, remaining: 0xc)
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
    echo "FAIL: Check cert range config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check request range objects"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
tests/ca/bin/ca-request-range-objects.sh -t legacy2 primaryds | tee output

# there should be no new range
cat > expected << EOF
SecurePort: 8443
beginRange: 11
endRange: 20
host: primary.example.com

SecurePort: 8443
beginRange: 21
endRange: 30
host: secondary.example.com

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
tests/ca/bin/ca-cert-range-objects.sh -t legacy2 primaryds | tee output

# there should be no new range
cat > expected << EOF
SecurePort: 8443
beginRange: 25
endRange: 42
host: primary.example.com

SecurePort: 8443
beginRange: 43
endRange: 60
host: secondary.example.com

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
tests/ca/bin/ca-request-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be the same
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
tests/ca/bin/ca-cert-next-range.sh -t legacy2 primaryds | tee output

# nextRange should be the same
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

step "Allocate new request range for primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki \
    -n caadmin \
    ca-job-start \
    serialNumberUpdate

# wait for DS replication
sleep 5
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Allocate new request range for primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 10 certs in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
for i in $(seq 1 10); do
    docker exec primary pki \
        -n caadmin \
        ca-cert-issue \
        --profile caUserCert \
        --csr-file testuser.csr \
        --output-file testuser.crt

    docker exec primary openssl x509 -in testuser.crt -serial -noout
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 10 certs in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 40 requests
seq 1 7 > expected     # primary CA
seq 16 20 >> expected  # secondary CA
seq 8 15 >> expected   # primary CA
seq 21 30 >> expected  # secondary CA
seq 31 40 >> expected  # primary CA

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
docker exec primary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 39 certs
printf "0x%x\n" {9..15} > expected    # primary CA
printf "0x%x\n" {16..24} >> expected  # secondary CA
printf "0x%x\n" {25..41} >> expected  # primary CA
printf "0x%x\n" {43..48} >> expected  # secondary CA

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Allocate new request range for primary CA again"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki \
    -n caadmin \
    ca-job-start \
    serialNumberUpdate

# wait for DS replication
sleep 5
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Allocate new request range for primary CA again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Enroll 1 cert in primary CA"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary pki \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser.csr \
    --output-file testuser.crt

docker exec primary openssl x509 -in testuser.crt -serial -noout
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll 1 cert in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check requests"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-cert-request-find | tee output
sed -n "s/^ *Request ID: *\(.*\)$/\1/p" output > actual

# there should be 41 requests
seq 1 7 > expected     # primary CA
seq 16 20 >> expected  # secondary CA
seq 8 15 >> expected   # primary CA
seq 21 30 >> expected  # secondary CA
seq 31 41 >> expected  # primary CA

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
docker exec primary pki-server ca-cert-find | tee output
sed -n "s/^ *Serial Number: *\(.*\)$/\1/p" output > actual

# there should be 40 certs without any gap
printf "0x%x\n" {9..15} > expected    # primary CA
printf "0x%x\n" {16..24} >> expected  # secondary CA
printf "0x%x\n" {25..42} >> expected  # primary CA
printf "0x%x\n" {43..48} >> expected  # secondary CA

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-ssnv2-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-ssnv2-test PASSED ===="
