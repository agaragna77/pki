#!/bin/bash
# Generated TMT port of .github/workflows/ipa-acme-test.yml
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
    docker rm -f client ipa 2>/dev/null || true
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
# Packages needed: podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v podman-docker >/dev/null 2>&1 || dnf install -y podman-docker 2>/dev/null || true
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

step "Retrieve IPA images"
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
    echo "FAIL: Retrieve IPA images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load IPA images"
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
    echo "FAIL: Load IPA images (rc=$_rc)" >&2
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

step "Run IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --image=ipa-runner \
    --hostname=ipa.example.com \
    --network=example \
    --network-alias=ipa.example.com \
    --network-alias=ipa-ca.example.com \
    ipa
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA server in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa sysctl net.ipv6.conf.lo.disable_ipv6=0
docker exec ipa ipa-server-install \
    -U \
    --domain example.com \
    -r EXAMPLE.COM \
    -p Secret.123 \
    -a Secret.123 \
    --no-host-dns \
    --no-ntp
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA server in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update PKI server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa dnf install -y xmlstarlet

# disable access log buffer
docker exec ipa xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart PKI server
docker exec ipa pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update PKI server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check DS server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa dsctl --list
docker exec ipa dsconf slapd-EXAMPLE-COM backend suffix list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 | docker exec -i ipa kinit admin
docker exec ipa ipa ping
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-kra-install -p Secret.123
docker exec ipa pki-server ca-connector-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check DS server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa dsctl --list
docker exec ipa dsconf slapd-EXAMPLE-COM backend suffix list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify CA admin in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec ipa pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ipa pki pkcs12-import \
    --pkcs12 /root/ca-agent.p12 \
    --pkcs12-password Secret.123
docker exec ipa pki -n ipa-ca-agent ca-user-show admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify CA admin in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable ACME in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-acme-manage enable
docker exec ipa ipa-acme-manage status
echo "Available" > expected
docker exec ipa bash -c "pki acme-info | sed -n 's/\s*Status:\s\+\(\S\+\).*/\1/p' > ${SHARED}/actual"
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ACME in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check DS server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa dsctl --list
docker exec ipa dsconf slapd-EXAMPLE-COM backend suffix list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Specify main CA as Authority ID for ACME in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
caid=$(docker exec ipa ipa -e in_server=true ca-show ipa --raw | sed -n 's/\s*ipacaid:\s\+\(\S\+\).*/\1/p' )
docker exec ipa pki-server acme-issuer-mod --type pki "-Dauthority-id=${caid}"
echo "${caid}" > expected
docker exec ipa bash -c "pki-server acme-issuer-show | sed -n 's/\s*Authority ID:\s\+\(\S\+\).*/\1/p' > ${SHARED}/actual"
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Specify main CA as Authority ID for ACME in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --detach \
    --name=client \
    --hostname=client.example.com \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    ipa-runner \
    /usr/sbin/init
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Connect client container to network"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker network connect example client --alias client.example.com
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Connect client container to network (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA client in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client sysctl net.ipv6.conf.lo.disable_ipv6=0
docker exec client ipa-client-install \
    -U \
    --server=ipa.example.com \
    --domain=example.com \
    --realm=EXAMPLE.COM \
    -p admin \
    -w Secret.123 \
    --no-ntp
docker exec client bash -c "echo Secret.123 | kinit admin"
docker exec client klist
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA client in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify certbot in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server https://ipa-ca.example.com/acme/directory \
    --email user1@example.com \
    --agree-tos \
    --non-interactive
docker exec client certbot certonly \
    --server https://ipa-ca.example.com/acme/directory \
    -d client.example.com \
    --key-type rsa \
     --standalone \
    --non-interactive
docker exec client certbot renew \
    --server https://ipa-ca.example.com/acme/directory \
    --cert-name client.example.com \
    --force-renewal \
    --non-interactive
docker exec client certbot revoke \
    --server https://ipa-ca.example.com/acme/directory \
    --cert-name client.example.com \
    --non-interactive
docker exec client certbot update_account \
    --server https://ipa-ca.example.com/acme/directory \
    --email user2@example.com \
    --non-interactive
docker exec client certbot unregister \
    --server https://ipa-ca.example.com/acme/directory \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify certbot in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Disable ACME in IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-acme-manage disable
docker exec ipa ipa-acme-manage status
echo "Unavailable" > expected
docker exec ipa bash -c "pki acme-info | sed -n 's/\s*Status:\s\+\(\S\+\).*/\1/p' > ${SHARED}/actual"
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Disable ACME in IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check IPA CA install log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/ipaserver-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA CA install log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD access logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/httpd/access_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD access logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD error logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/httpd/error_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD error logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa journalctl -x --no-pager -u dirsrv@EXAMPLE-COM.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS access logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/dirsrv/slapd-EXAMPLE-COM/access
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS access logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS error logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/dirsrv/slapd-EXAMPLE-COM/errors
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS error logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS security logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/dirsrv/slapd-EXAMPLE-COM/security
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS security logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA pkispawn log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/log/pki -name "pki-ca-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkispawn log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
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
docker exec ipa find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
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
docker exec ipa find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove IPA server from IPA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-server-install --uninstall -U
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove IPA server from IPA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA pkidestroy log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/log/pki -name "pki-ca-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkidestroy log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ipa-acme-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ipa-acme-test PASSED ===="
