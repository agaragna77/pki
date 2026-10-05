#!/bin/bash
# Generated TMT port of .github/workflows/ipa-reinstall-test.yml
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
    docker rm -f ipa 2>/dev/null || true
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

step "Install IPA server"
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
    echo "FAIL: Install IPA server (rc=$_rc)" >&2
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

step "Import CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec ipa pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ipa pki nss-cert-show ca_signing | tee ca_signing.orig
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA agent cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -l /root

docker exec ipa pki pkcs12-import \
    --pkcs12 /root/ca-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-show ipa-ca-agent | tee ipa-ca-agent.orig

# CA agent should be able to access CA users
docker exec ipa pki -n ipa-ca-agent ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA agent cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check RA agent cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -l /var/lib/ipa

# import RA agent cert and key into PKCS #12 file
docker exec ipa openssl pkcs12 -export \
    -in /var/lib/ipa/ra-agent.pem \
    -inkey /var/lib/ipa/ra-agent.key \
    -out ra-agent.p12 \
    -passout pass:Secret.123 \
    -name ipa-ra-agent

# import PKCS #12 file into NSS database
docker exec ipa pki pkcs12-import \
    --pkcs12 ra-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-show ipa-ra-agent | tee ipa-ra-agent.orig

# RA agent should be able to access cert requests
docker exec ipa pki -n ipa-ra-agent ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check RA agent cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-kra-install -p Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# CA agent should be able to access KRA users
docker exec ipa pki -n ipa-ca-agent kra-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users (rc=$_rc)" >&2
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

step "Check IPA KRA install log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/ipaserver-kra-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA KRA install log (rc=$_rc)" >&2
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove IPA server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-server-install --uninstall -U
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove IPA server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check /etc/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /etc/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /etc/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /var/lib/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /var/lib/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /var/lib/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /var/log/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /var/log/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /var/log/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /root/.dogtag after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -lR /root/.dogtag
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /root/.dogtag after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA server again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-server-install \
    -U \
    --domain example.com \
    -r EXAMPLE.COM \
    -p Secret.123 \
    -a Secret.123 \
    --no-host-dns \
    --no-ntp

echo Secret.123 | docker exec -i ipa kinit admin
docker exec ipa ipa ping
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA server again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA signing cert again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create new NSS database
docker exec ipa pki nss-create --force

docker exec ipa pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec ipa pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ipa pki nss-cert-show ca_signing | tee ca_signing.new

# CA signing cert should be different
rc=0
diff ca_signing.orig ca_signing.new || rc=$?

[ $rc -ne 0 ]
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA agent cert again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -l /root

docker exec ipa pki pkcs12-import \
    --pkcs12 /root/ca-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-show ipa-ca-agent | tee ipa-ca-agent.new

# CA agent cert should be different
rc=0
diff ipa-ca-agent.orig ipa-ca-agent.new || rc=$?

[ $rc -ne 0 ]

# CA agent should be able to access CA users
docker exec ipa pki -n ipa-ca-agent ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA agent cert again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check RA agent cert again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -l /var/lib/ipa

# import RA agent cert and key into PKCS #12 file
docker exec ipa openssl pkcs12 -export \
    -in /var/lib/ipa/ra-agent.pem \
    -inkey /var/lib/ipa/ra-agent.key \
    -out ra-agent.p12 \
    -passout pass:Secret.123 \
    -name ipa-ra-agent

# import PKCS #12 file into NSS database
docker exec ipa pki pkcs12-import \
    --pkcs12 ra-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-show ipa-ra-agent | tee ipa-ra-agent.new

# RA agent cert should be different
rc=0
diff ipa-ra-agent.orig ipa-ra-agent.new || rc=$?

[ $rc -ne 0 ]

# RA agent should be able to access cert requests
docker exec ipa pki -n ipa-ra-agent ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check RA agent cert again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-kra-install -p Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA again (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA users again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# CA agent should be able to access KRA users
docker exec ipa pki -n ipa-ca-agent kra-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users again (rc=$_rc)" >&2
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

step "Check IPA KRA install log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa cat /var/log/ipaserver-kra-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA KRA install log (rc=$_rc)" >&2
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

step "Check KRA pkispawn log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/log/pki -name "pki-kra-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkispawn log (rc=$_rc)" >&2
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove IPA server again"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-server-install --uninstall -U
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove IPA server again (rc=$_rc)" >&2
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

step "Check KRA pkidestroy log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa find /var/log/pki -name "pki-kra-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkidestroy log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /etc/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /etc/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /etc/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /var/lib/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /var/lib/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /var/lib/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /var/log/pki after removal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ipa ls -lR /var/log/pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /var/log/pki after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check /root/.dogtag after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -lR /root/.dogtag
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check /root/.dogtag after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ipa-reinstall-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ipa-reinstall-test PASSED ===="
