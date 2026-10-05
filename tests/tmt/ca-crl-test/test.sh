#!/bin/bash
# Generated TMT port of .github/workflows/ca-crl-test.yml
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

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: libxml2-utils
# Most are available in the pki-runner container or Fedora host.
command -v libxml2-utils >/dev/null 2>&1 || dnf install -y libxml2-utils 2>/dev/null || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

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

step "Check pki ca-crl CLI help messages"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-crl-update --help
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-crl CLI help messages (rc=$_rc)" >&2
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

step "Configure caUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 1 minute
VALIDITY_DEFAULT="policyset.userCertSet.2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=1/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caUserCert.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure caUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL issuing points"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-crl-ip-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL issuing points (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update CRL configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# update cert status every minute
docker exec pki pki-server ca-config-set ca.certStatusUpdateInterval 60

# update CRL immediately after each cert revocation
docker exec pki pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL

docker exec pki pki-server ca-crl-ip-show MasterCRL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update CRL configuration (rc=$_rc)" >&2
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

step "Run PKI healthcheck"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Retry pki-healthcheck: intermittent NSS load timeout on audit_signing
hc_ok=0
for hc_try in 1 2 3; do
    echo "pki-healthcheck attempt ${hc_try}/3"
    if (
    set -euo pipefail
    docker exec pki pki-healthcheck --failures-only
    ); then
        hc_ok=1
        break
    fi
    sleep 5
done
[[ "$hc_ok" -eq 1 ]]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run PKI healthcheck (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize PKI client"
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize PKI client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial CRL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be no revoked certs
docker exec pki pki-server ca-crl-record-show MasterCRL | tee output

sed -n \
    -e '/^\s*CRL Number:/p' \
    -e '/^\s*CRL Size:/p' \
    output > actual

cat > expected << EOF
  CRL Number: 0x1
  CRL Size: 0
EOF

diff expected actual

docker exec pki pki-server ca-crl-record-cert-find MasterCRL | tee output

diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CRL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request uid=testuser1 | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > cert.id

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
docker exec pki pki -n caadmin ca-cert-hold $CERT_ID --force

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be revoked
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after user 1 cert revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be one revoked cert
docker exec pki pki-server ca-crl-record-show MasterCRL | tee output

sed -n \
    -e '/^\s*CRL Number:/p' \
    -e '/^\s*CRL Size:/p' \
    output > actual

cat > expected << EOF
  CRL Number: 0x2
  CRL Size: 1
EOF

diff expected actual

docker exec pki pki-server ca-crl-record-cert-find MasterCRL | tee output

sed -n \
    -e '/^\s*Serial Number:/p' \
    -e '/^\s*Reason:/p' \
    output > actual

CERT_ID=$(cat cert.id)
cat > expected << EOF
  Serial Number: $CERT_ID
  Reason: CERTIFICATE_HOLD
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after user 1 cert revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check VLV usage in DS access log"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Check if VLV index was used during CRL generation
# The query for revoked certs should use the allRevokedCertsByIssuer VLV index
echo "Checking DS access log for VLV usage during CRL generation:"
docker exec ds sh -c "grep 'certStatus=REVOKED' /var/log/dirsrv/slapd-localhost/access* || true"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check VLV usage in DS access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Unrevoke user 1 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
docker exec pki pki -n caadmin ca-cert-release-hold $CERT_ID --force

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Unrevoke user 1 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after user 1 cert unrevocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be no revoked certs
docker exec pki pki-server ca-crl-record-show MasterCRL | tee output

sed -n \
    -e '/^\s*CRL Number:/p' \
    -e '/^\s*CRL Size:/p' \
    output > actual

cat > expected << EOF
  CRL Number: 0x3
  CRL Size: 0
EOF

diff expected actual

docker exec pki pki-server ca-crl-record-cert-find MasterCRL | tee output

diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after user 1 cert unrevocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll user 2 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki client-cert-request uid=testuser2 | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec pki pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output
CERT_ID=$(sed -n -e 's/^ *Certificate ID: *\(.*\)$/\1/p' output)
echo "CERT_ID: $CERT_ID"
echo $CERT_ID > cert.id

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be valid
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "VALID" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll user 2 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke user 2 cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_ID=$(cat cert.id)
docker exec pki pki -n caadmin ca-cert-hold $CERT_ID --force

docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be revoked
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke user 2 cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after user 2 cert revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be one revoked cert
docker exec pki pki-server ca-crl-record-show MasterCRL | tee output

sed -n \
    -e '/^\s*CRL Number:/p' \
    -e '/^\s*CRL Size:/p' \
    output > actual

cat > expected << EOF
  CRL Number: 0x4
  CRL Size: 1
EOF

diff expected actual

docker exec pki pki-server ca-crl-record-cert-find MasterCRL | tee output

sed -n \
    -e '/^\s*Serial Number:/p' \
    -e '/^\s*Reason:/p' \
    output > actual

CERT_ID=$(cat cert.id)
cat > expected << EOF
  Serial Number: $CERT_ID
  Reason: CERTIFICATE_HOLD
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after user 2 cert revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for user 2 cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120

CERT_ID=$(cat cert.id)
docker exec pki pki ca-cert-show $CERT_ID | tee output

# cert should be revoked and expired
sed -n "s/^ *Status: \(.*\)$/\1/p" output > actual
echo "REVOKED_EXPIRED" > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for user 2 cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Force CRL update after user 2 cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# force CRL update
docker exec pki pki -n caadmin ca-crl-update

# wait for CRL update
sleep 10
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Force CRL update after user 2 cert expiration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL after user 2 cert expiration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be no revoked certs
docker exec pki pki-server ca-crl-record-show MasterCRL | tee output

sed -n \
    -e '/^\s*CRL Number:/p' \
    -e '/^\s*CRL Size:/p' \
    output > actual

cat > expected << EOF
  CRL Number: 0x5
  CRL Size: 0
EOF

diff expected actual

docker exec pki pki-server ca-crl-record-cert-find MasterCRL | tee output

diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL after user 2 cert expiration (rc=$_rc)" >&2
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
    echo "==== ca-crl-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-crl-test PASSED ===="
