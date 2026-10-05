#!/bin/bash
# Generated TMT port of .github/workflows/ipa-subca-test.yml
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

step "Create root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki \
    -d nssdb \
    nss-cert-request \
    --subject "CN=Root CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr root-ca_signing.csr
docker exec ipa pki \
    -d nssdb \
    nss-cert-issue \
    --csr root-ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert root-ca_signing.crt

docker exec ipa pki \
    -d nssdb \
    nss-cert-import \
    --cert root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate IPA cert request"
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
    --no-ntp \
    --external-ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate IPA cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue IPA cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki \
    -d nssdb \
    nss-cert-issue \
    --issuer root-ca_signing \
    --csr /root/ipa.csr \
    --ext /usr/share/pki/server/certs/subca_signing.conf \
    --cert ipa.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue IPA cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA server with Sub-CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ipa-server-install \
    --external-cert-file=/ipa.crt \
    --external-cert-file=/root-ca_signing.crt \
    -p Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA server with Sub-CA (rc=$_rc)" >&2
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

docker exec ipa pki nss-cert-import \
    --cert root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec ipa pki nss-cert-import \
    --cert ipa.crt \
    ca_signing

docker exec ipa pki pkcs12-import \
    --pkcs12 /root/ca-agent.p12 \
    --pkcs12-password Secret.123

docker exec ipa pki -n ipa-ca-agent ca-user-show admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check lightweight CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 1 authority initially
docker exec ipa pki -n ipa-ca-agent ca-authority-find | tee output
echo "1" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check lightweight CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create lightweight CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
for i in {1..20}
do
    docker exec ipa ipa ca-add "lwca$i" \
        --subject "cn=Lightweight CA $i" \
        --desc "Lightweight CA $i"
done

# there should be 21 authorities now
docker exec ipa pki -n ipa-ca-agent ca-authority-find | tee output
echo "21" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create lightweight CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate certificate in the CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
for i in {1..20}
do
    docker exec ipa ipa caacl-add-ca hosts_services_caIPAserviceCert --cas=lwca$i
    docker exec ipa mkdir /tmp/lwca$i
    docker exec ipa ipa-getcert request -w -k /tmp/lwca$i/test$i.key -f /tmp/lwca$i/test$i.pem -X lwca$i
    docker exec ipa openssl x509 -in /tmp/lwca$i/test$i.pem -noout -subject -issuer
done
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate certificate in the CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove lightweight CAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
for i in {1..20}
do
    docker exec ipa ipa ca-disable "lwca$i"
    docker exec ipa ipa ca-del "lwca$i"
done

# there should be 1 authority now
docker exec ipa pki -n ipa-ca-agent ca-authority-find | tee output
echo "1" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove lightweight CAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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
    echo "==== ipa-subca-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ipa-subca-test PASSED ===="
