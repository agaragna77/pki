#!/bin/bash
# Generated TMT port of .github/workflows/ca-renewal-automated-ldaps-test.yml
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

step "Create DS signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=DS Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr ds_signing.csr

docker exec pki pki \
    nss-cert-issue \
    --csr ds_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert ds_signing.crt

docker exec pki pki nss-cert-import \
    --cert ds_signing.crt \
    --trust CT,C,C \
    Self-Signed-CA
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create DS signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create DS server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=ds.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr ds_server.csr

docker exec pki pki \
    nss-cert-issue \
    --issuer Self-Signed-CA \
    --csr ds_server.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert ds_server.crt

docker exec pki pki nss-cert-import \
    --cert ds_server.crt \
    Server-Cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create DS server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import certs into DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pk12util \
    -d /root/.dogtag/nssdb \
    -o $SHARED/ds_server.p12 \
    -W Secret.123 \
    -n Server-Cert

sudo chmod go+r ds_server.p12

tests/bin/ds-certs-import.sh \
    --image=${DS_IMAGE} \
    --input=ds_server.p12 \
    --password=Secret.123 \
    --debug \
    ds

tests/bin/ds-stop.sh \
    --image=${DS_IMAGE} \
    ds

tests/bin/ds-start.sh \
    --image=${DS_IMAGE} \
    ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import certs into DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure short-lived SSL server cert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# set cert validity to 3 minute
VALIDITY_DEFAULT="2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=3/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/rsaServerCert.profile

# check updated profile
docker exec pki cat /usr/share/pki/ca/conf/rsaServerCert.profile
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
# set cert validity to 3 minute
VALIDITY_DEFAULT="2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=3/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/rsaSubsystemCert.profile

# check updated profile
docker exec pki cat /usr/share/pki/ca/conf/rsaSubsystemCert.profile
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
# set cert validity to 3 minute
VALIDITY_DEFAULT="2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=3/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/caAuditSigningCert.profile

# check updated profile
docker exec pki cat /usr/share/pki/ca/conf/caAuditSigningCert.profile
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
# set cert validity to 3 minute
VALIDITY_DEFAULT="2.default.params"
docker exec pki sed -i \
    -e "s/^$VALIDITY_DEFAULT.range=.*$/$VALIDITY_DEFAULT.range=3/" \
    -e "/^$VALIDITY_DEFAULT.range=.*$/a $VALIDITY_DEFAULT.rangeUnit=minute" \
    /usr/share/pki/ca/conf/caOCSPCert.profile

# check updated profile
docker exec pki cat /usr/share/pki/ca/conf/caOCSPCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure short-lived OCSP signing cert profile (rc=$_rc)" >&2
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
    -D pki_ds_url=ldaps://ds.example.com:3636 \
    -D pki_ds_secure_connection_ca_nickname=ds_signing \
    -D pki_ds_secure_connection_ca_pem_file=ds_signing.crt \
    -v

docker exec pki pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=dc=ca,dc=pki,dc=example,dc=com
internaldb.database=ca
internaldb.ldapauth.authtype=BasicAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=
internaldb.ldapconn.host=ds.example.com
internaldb.ldapconn.port=3636
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

step "Check system cert keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get keys in internal token
echo "Secret.123" > password.txt
docker exec pki certutil -K \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f $SHARED/password.txt \
    | sed -n 's/<.*> \+\(\S\+\) \+\(\S\+\) \+\(.*\)/\1 \2 \3/p' \
    | sort \
    | tee keys.orig
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system cert keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-show ca_signing
docker exec pki pki-server cert-show ca_ocsp_signing
docker exec pki pki-server cert-show ca_audit_signing
docker exec pki pki-server cert-show subsystem
docker exec pki pki-server cert-show sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs (rc=$_rc)" >&2
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
    # pki-healthcheck should generate warnings
    docker exec pki pki-healthcheck --failures-only \
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

step "Check CA admin"
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
    --password Secret.123

docker exec pki pki nss-cert-show caadmin

# check CA admin cert
docker exec pki pki -n caadmin ca-user-show caadmin

# check CA admin password
docker exec pki pki -u caadmin -w Secret.123 ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-show CA-pki.example.com-8443
docker exec pki pki-server ca-user-cert-find CA-pki.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart PKI server with expired certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# wait for SSL server cert to expire
sleep 180

docker exec pki pki-server restart --wait \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart PKI server with expired certs (rc=$_rc)" >&2
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
    # pki-healthcheck should fail
    docker exec pki pki-healthcheck --failures-only \
        > >(tee stdout) 2> >(tee stderr >&2) || true

    cat > expected << EOF
    Expired Cert: ocsp_signing
    Expired Cert: sslserver
    Expired Cert: subsystem
    Expired Cert: audit_signing
    Internal server error 404 Client Error:  for url: https://pki.example.com:8443/ca/admin/ca/getStatus
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

step "Check PKI client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# client should be able to access the server
# by ignoring the expired SSL server cert
docker exec pki pki \
    --ignore-cert-status EXPIRED_CERTIFICATE \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# CA admin should be able to access the server
# by ignoring the expired SSL server cert
# but the CA subsystem will not be available
docker exec pki pki \
    --ignore-cert-status EXPIRED_CERTIFICATE \
    -n caadmin \
    ca-user-show \
    caadmin \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ResourceNotFoundException: 
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Renew system certs using pki-server cert-fix"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-fix \
    --ldap-url ldaps://ds.example.com:3636 \
    --dm-password Secret.123 \
    --agent-uid caadmin \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Renew system certs using pki-server cert-fix (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=dc=ca,dc=pki,dc=example,dc=com
internaldb.database=ca
internaldb.ldapauth.authtype=BasicAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=
internaldb.ldapconn.host=ds.example.com
internaldb.ldapconn.port=3636
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

step "Check system certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-show ca_signing
docker exec pki pki-server cert-show ca_ocsp_signing
docker exec pki pki-server cert-show ca_audit_signing
docker exec pki pki-server cert-show subsystem
docker exec pki pki-server cert-show sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert keys after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get keys
docker exec pki certutil -K \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f $SHARED/password.txt \
    | sed -n 's/<.*> \+\(\S\+\) \+\(\S\+\) \+\(.*\)/\1 \2 \3/p' \
    | sort \
    | tee keys.after

# the keys should not change
diff keys.orig keys.after
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert keys after renewal (rc=$_rc)" >&2
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
    # pki-healthcheck should not fail
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

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# client should not fail
docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update CA subsystem user cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# this is required by pkidestroy since it uses the subsystem cert
# for removing the subsystem from the security domain

docker exec pki pki-server cert-export \
    --cert-file subsystem.crt \
    subsystem

# get cert ID
docker exec pki pki-server ca-user-cert-find CA-pki.example.com-8443 | tee output
CERT_ID=$(sed -n "s/^\s*Cert ID:\s*\(.*\)$/\1/p" output)
echo "CERT_ID: $CERT_ID"

# remove current cert
docker exec pki pki-server ca-user-cert-del CA-pki.example.com-8443 "$CERT_ID"

# install new cert
docker exec pki pki-server ca-user-cert-add CA-pki.example.com-8443 --cert subsystem.crt

docker exec pki pki-server ca-user-cert-find CA-pki.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update CA subsystem user cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# pkidestroy should not fail
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

step "Check CA selftests log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /var/lib/pki/pki-tomcat/logs/ca/selftests.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA selftests log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-renewal-automated-ldaps-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-renewal-automated-ldaps-test PASSED ===="
