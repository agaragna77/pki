#!/bin/bash
# Generated TMT port of .github/workflows/ca-profile-caServerCert-test.yml
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

step "Configure caServerCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# allow user-specified SAN extension
docker exec pki sed -i \
    -e "s/^\(policyset.serverCertSet.list\)=\(.*\)$/\1=\2,13/" \
    -e '$ a policyset.serverCertSet.13.constraint.class_id=noConstraintImpl' \
    -e '$ a policyset.serverCertSet.13.constraint.name=No Constraint' \
    -e '$ a policyset.serverCertSet.13.default.class_id=userExtensionDefaultImpl' \
    -e '$ a policyset.serverCertSet.13.default.name=User supplied extension in CSR' \
    -e '$ a policyset.serverCertSet.13.default.params.userExtOID=2.5.29.17' \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg

# require unique subject name
docker exec pki sed -i \
    -e "s/^\(policyset.serverCertSet.list\)=\(.*\)$/\1=\2,14/" \
    -e '$ a policyset.serverCertSet.14.constraint.class_id=uniqueSubjectNameConstraintImpl' \
    -e '$ a policyset.serverCertSet.14.constraint.name=Unique Subject Name Constraint' \
    -e '$ a policyset.serverCertSet.14.default.class_id=noDefaultImpl' \
    -e '$ a policyset.serverCertSet.14.default.name=No Default' \
    /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg

# check updated profile
docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/profiles/ca/caServerCert.cfg

docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure caServerCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA admin"
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
    echo "FAIL: Set up CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate cert request
docker exec pki pki \
    nss-cert-request \
    --subject "CN=server.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --subjectAltName "critical, DNS:www.example.com" \
    --csr sslserver.csr

docker exec pki openssl req -text -noout -in sslserver.csr | tee output

# verify SAN extension in cert request
echo "X509v3 Subject Alternative Name: critical" > expected
echo "DNS:www.example.com" >> expected
sed -En 'N; s/^ *(X509v3 Subject Alternative Name: .*)\n *(.*)$/\1\n\2/p; D' output | tee actual
diff actual expected

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file sslserver.csr \
    --output-file sslserver.crt

docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# verfiy SAN extension in cert
echo "X509v3 Subject Alternative Name: critical" > expected
echo "DNS:www.example.com" >> expected
sed -En 'N; s/^ *(X509v3 Subject Alternative Name: .*)\n *(.*)$/\1\n\2/p; D' output | tee actual
diff actual expected
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert with same subject name"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate cert request
docker exec pki pki \
    nss-cert-request \
    --subject "CN=server.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --subjectAltName "critical, DNS:pki.example.com" \
    --csr sslserver.csr

docker exec pki openssl req -text -noout -in sslserver.csr | tee output

# verify SAN extension
echo "X509v3 Subject Alternative Name: critical" > expected
echo "DNS:pki.example.com" >> expected
sed -En 'N; s/^ *(X509v3 Subject Alternative Name: .*)\n *(.*)$/\1\n\2/p; D' output | tee actual
diff actual expected

# issue cert
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file sslserver.csr \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# request should be rejected by UniqueSubjectNameConstraint
cat > expected << EOF
ERROR: Request rejected: Subject Name Not Unique CN=server.example.com
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert with same subject name (rc=$_rc)" >&2
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
    echo "==== ca-profile-caServerCert-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-profile-caServerCert-test PASSED ===="
