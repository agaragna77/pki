#!/bin/bash
# Generated TMT port of .github/workflows/ipa-renewal-test.yml
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

step "Configure short-lived SSL server cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 10 minute
VALIDITY_DEFAULT="2.default.params"
docker exec ipa sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=10/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/rsaServerCert.profile

docker exec ipa cat /usr/share/pki/ca/conf/rsaServerCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived SSL server cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure short-lived subsystem cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 10 minute
VALIDITY_DEFAULT="2.default.params"
docker exec ipa sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=10/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/rsaSubsystemCert.profile

docker exec ipa cat /usr/share/pki/ca/conf/rsaSubsystemCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived subsystem cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure short-lived audit signing cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 10 minute
VALIDITY_DEFAULT="2.default.params"
docker exec ipa sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=10/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/caAuditSigningCert.profile

docker exec ipa cat /usr/share/pki/ca/conf/caAuditSigningCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived audit signing cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure short-lived OCSP signing cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 10 minute
VALIDITY_DEFAULT="2.default.params"
docker exec ipa sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=10/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/caOCSPCert.profile

docker exec ipa cat /usr/share/pki/ca/conf/caOCSPCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived OCSP signing cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure short-lived admin cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 10 minute
VALIDITY_DEFAULT="2.default.params"
docker exec ipa sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=10/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/rsaAdminCert.profile

docker exec ipa cat /usr/share/pki/ca/conf/rsaAdminCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived admin cert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA server with CA"
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

docker exec ipa pki-server cert-export ca_signing --cert-file ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA server with CA (rc=$_rc)" >&2
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

step "Check HTTPD certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /var/lib/ipa/certs
docker exec ipa openssl x509 -text -noout -in /var/lib/ipa/certs/httpd.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check DS certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-find
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-show "EXAMPLE.COM IPA CA"
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-show "Server-Cert"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check certs
docker exec ipa pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=o=ipaca
internaldb.database=ipaca
internaldb.ldapauth.authtype=SslClientAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=subsystemCert cert-pki-ca
internaldb.ldapconn.host=ipa.example.com
internaldb.ldapconn.port=636
internaldb.ldapconn.secureConn=true
internaldb.maxConns=15
internaldb.minConns=3
internaldb.multipleSuffix.enable=false
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA database config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /root/.dogtag/pki-tomcat
docker exec ipa cat /root/.dogtag/pki-tomcat/ca_admin.cert
#docker exec ipa openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert

# import CA admin cert and key into the client's NSS database
docker exec ipa pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ipa pki pkcs12-import \
    --pkcs12 /root/ca-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-find
docker exec ipa pki nss-cert-show ipa-ca-agent

# CA admin should be able to access PKI users
docker exec ipa pki -n ipa-ca-agent --ignore-cert-status EXPIRED_CERTIFICATE ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check RA agent cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /var/lib/ipa
docker exec ipa openssl x509 -text -noout -in /var/lib/ipa/ra-agent.pem

# import RA agent cert and key into a PKCS #12 file
# then import it into the client's NSS database
docker exec ipa openssl pkcs12 -export \
    -in /var/lib/ipa/ra-agent.pem \
    -inkey /var/lib/ipa/ra-agent.key \
    -out ra-agent.p12 \
    -passout pass:Secret.123 \
    -name ipa-ra-agent

docker exec ipa pki pkcs12-import \
    --pkcs12 ra-agent.p12 \
    --password Secret.123

docker exec ipa pki nss-cert-find
docker exec ipa pki nss-cert-show ipa-ra-agent

# RA agent should be able to access cert requests
docker exec ipa pki -n ipa-ra-agent --ignore-cert-status EXPIRED_CERTIFICATE ca-cert-request-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check RA agent cert (rc=$_rc)" >&2
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
    docker exec ipa pki-healthcheck --failures-only \
        > >(tee stdout) 2> >(tee stderr >&2) || true

    cat > expected << EOF
    Expiring in a day: ocsp_signing
    Expiring in a day: sslserver
    Expiring in a day: subsystem
    Expiring in a day: audit_signing
    EOF

    diff expected stderr
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

step "Renew certs using ipa-cert-fix"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo yes | docker exec -i ipa ipa-cert-fix
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Renew certs using ipa-cert-fix (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check HTTPD certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /var/lib/ipa/certs
docker exec ipa openssl x509 -text -noout -in /var/lib/ipa/certs/httpd.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check DS certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-find
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-show "EXAMPLE.COM IPA CA"
docker exec ipa pki -d /etc/dirsrv/slapd-EXAMPLE-COM nss-cert-show "Server-Cert"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=o=ipaca
internaldb.database=ipaca
internaldb.ldapauth.authtype=SslClientAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=subsystemCert cert-pki-ca
internaldb.ldapconn.host=ipa.example.com
internaldb.ldapconn.port=636
internaldb.ldapconn.secureConn=true
internaldb.maxConns=15
internaldb.minConns=3
internaldb.multipleSuffix.enable=false
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA database config after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI system certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI system certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /root/.dogtag/pki-tomcat
docker exec ipa cat /root/.dogtag/pki-tomcat/ca_admin.cert
docker exec ipa openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check RA agent cert after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ipa ls -la /var/lib/ipa
docker exec ipa openssl x509 -text -noout -in /var/lib/ipa/ra-agent.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check RA agent cert after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck after renewal"
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
    docker exec ipa pki-healthcheck --failures-only \
        > >(tee stdout) 2> >(tee stderr >&2) || true

    diff /dev/null stderr
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
    echo "FAIL: Run PKI healthcheck after renewal (rc=$_rc)" >&2
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
    echo "==== ipa-renewal-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ipa-renewal-test PASSED ===="
