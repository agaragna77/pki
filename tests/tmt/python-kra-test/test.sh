#!/bin/bash
# Generated TMT port of .github/workflows/python-kra-test.yml
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

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update PKI server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y xmlstarlet

# disable access log buffer
docker exec pki xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart PKI server
docker exec pki pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update PKI server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

# export admin cert
docker exec pki openssl pkcs12 \
   -in /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
   -passin pass:Secret.123 \
   -out admin.crt \
   -clcerts \
   -nokeys

# export admin key
docker exec pki openssl pkcs12 \
   -in /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
   -passin pass:Secret.123 \
   -out admin.key \
   -nodes \
   -nocerts
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/bin/pki-info.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -1 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server info with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/bin/pki-info.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --api v1 \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -1 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1 as specified
cat > expected << EOF
GET /pki/v1/info HTTP/1.1 200 -
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server info with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-user-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
GET /kra/v2/admin/users HTTP/1.1 200 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA users with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-user-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1 as specified
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
GET /kra/v1/admin/users HTTP/1.1 200 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert with key archival"
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

# get transport cert
docker exec pki pki-server cert-export \
    --cert-file kra_transport.crt \
    kra_transport

docker exec pki pki nss-cert-import \
    --cert kra_transport.crt \
    kra_transport

# create request
docker exec pki pki nss-cert-request \
    --type crmf \
    --format DER \
    --subject "UID=testuser" \
    --transport kra_transport \
    --csr testuser.csr \
    --debug

# issue cert
docker exec pki pki \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --request-format DER \
    --csr-file testuser.csr \
    --profile caUserCert \
    --subject "UID=testuser" \
    --output-file testuser.crt \
    --debug
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert with key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key requests"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-request-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
GET /kra/v2/agent/keyrequests HTTP/1.1 200 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key requests with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-request-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
GET /kra/v1/agent/keyrequests HTTP/1.1 200 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key requests with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    -v \
    | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > key.id

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
GET /kra/v2/agent/keys HTTP/1.1 200 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived keys with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-find.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
GET /kra/v1/agent/keys HTTP/1.1 200 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived keys with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change key status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-mod.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --status inactive \
    $KEY_ID \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
POST /kra/v2/agent/keys/$KEY_ID?status=inactive HTTP/1.1 204 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change key status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change key status with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat key.id)
echo "Key ID: $KEY_ID"

docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-mod.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    --status inactive \
    $KEY_ID \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
POST /kra/v1/agent/keys/$KEY_ID?status=inactive HTTP/1.1 204 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change key status with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Archive secret"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate random secret
head -c 1K < /dev/urandom > secret.archived

docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-archive.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --client-key-id testuser1 \
    --transport kra_transport.crt \
    --input $SHARED/secret.archived \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
POST /kra/v2/agent/keyrequests HTTP/1.1 201 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Archive secret (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve secret"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-retrieve.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --client-key-id testuser1 \
    --transport kra_transport.crt \
    --output $SHARED/secret.retrieved \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v2 by default
cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /kra/v2/account/login HTTP/1.1 200 kraadmin
GET /kra/v2/agent/keys?clientKeyID=testuser1 HTTP/1.1 200 kraadmin
POST /kra/v2/agent/keys/retrieve HTTP/1.1 200 kraadmin
GET /kra/v2/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output

diff secret.archived secret.retrieved
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve secret (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Archive secret with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-archive.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    --client-key-id testuser2 \
    --transport kra_transport.crt \
    --input $SHARED/secret.archived \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -3 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
POST /kra/v1/agent/keyrequests HTTP/1.1 201 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Archive secret with REST API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve secret with REST API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki python /usr/share/pki/tests/kra/bin/pki-kra-key-retrieve.py \
    -U https://pki.example.com:8443 \
    --ca-bundle ca_signing.crt \
    --client-cert admin.crt \
    --client-key admin.key \
    --api v1 \
    --client-key-id testuser2 \
    --transport kra_transport.crt \
    --output $SHARED/secret.retrieved \
    -v

sleep 1

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

# Python API should use REST API v1
cat > expected << EOF
GET /kra/v1/account/login HTTP/1.1 200 kraadmin
GET /kra/v1/agent/keys?clientKeyID=testuser2 HTTP/1.1 200 kraadmin
POST /kra/v1/agent/keys/retrieve HTTP/1.1 200 kraadmin
GET /kra/v1/account/logout HTTP/1.1 204 kraadmin
EOF

diff expected output

diff secret.archived secret.retrieved
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve secret with REST API v1 (rc=$_rc)" >&2
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== python-kra-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== python-kra-test PASSED ===="
