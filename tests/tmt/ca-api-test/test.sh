#!/bin/bash
# Generated TMT port of .github/workflows/ca-api-test.yml
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
    -D pki_audit_signing_nickname= \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Disable access log buffer"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y xmlstarlet

docker exec pki xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Disable access log buffer (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure RESTEasy logging"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i pki tee /var/lib/pki/pki-tomcat/conf/ca/logging.properties << EOF
org.jboss.resteasy.level = INFO
EOF

docker exec pki chown pkiuser:pkiuser /var/lib/pki/pki-tomcat/conf/ca/logging.properties
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure RESTEasy logging (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA signing cert"
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki info with default API"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki info

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -1 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki info with default API (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki info with API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki --api v1 info

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -1 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v1/info HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki info with API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-cert-find with default API"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# get certs returned
{ grep "Serial Number:" output || true; } | wc -l > actual
# there should be 5 certs returned
echo "5" > expected
diff expected actual

# get total certs found
sed -n "s/^\(\S*\) entries found$/\1/p" output > actual

# there should be no total certs found
diff /dev/null actual

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -2 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
POST /ca/v2/certs/search HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-cert-find with default API (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-cert-find with API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki --api v1 ca-cert-find | tee output

# get certs returned
{ grep "Serial Number:" output || true; } | wc -l > actual
# there should be 5 certs returned
echo "5" > expected
diff expected actual

# get total certs found
sed -n "s/^\(\S*\) entries found$/\1/p" output > actual

# there should be 5 certs found
echo "5" > expected
diff expected actual

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -2 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v1/info HTTP/1.1 200 -
POST /ca/v1/certs/search HTTP/1.1 200 -
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-cert-find with API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-user-show with default API"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-user-show caadmin

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /ca/v2/account/login HTTP/1.1 200 caadmin
GET /ca/v2/admin/users/caadmin HTTP/1.1 200 caadmin
GET /ca/v2/account/logout HTTP/1.1 204 caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-user-show with default API (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-user-show with API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin --api v1 ca-user-show caadmin

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v1/info HTTP/1.1 200 -
GET /ca/v1/account/login HTTP/1.1 200 caadmin
GET /ca/v1/admin/users/caadmin HTTP/1.1 200 caadmin
GET /ca/v1/account/logout HTTP/1.1 204 caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-user-show with API v1 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-cert-request-find with default API"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-cert-request-find

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v2/info HTTP/1.1 200 -
GET /ca/v2/account/login HTTP/1.1 200 caadmin
GET /ca/v2/agent/certrequests HTTP/1.1 200 caadmin
GET /ca/v2/account/logout HTTP/1.1 204 caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-cert-request-find with default API (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki ca-cert-request-find with API v1"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin --api v1 ca-cert-request-find

# check HTTP methods, paths, protocols, status, and authenticated users
docker exec pki find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -4 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output

cat > expected << EOF
GET /pki/v1/info HTTP/1.1 200 -
GET /ca/v1/account/login HTTP/1.1 200 caadmin
GET /ca/v1/agent/certrequests HTTP/1.1 200 caadmin
GET /ca/v1/account/logout HTTP/1.1 204 caadmin
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki ca-cert-request-find with API v1 (rc=$_rc)" >&2
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

step "Check for PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -l
docker exec pki find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for PKI core dumps (rc=$_rc)" >&2
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
    echo "==== ca-api-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-api-test PASSED ===="
