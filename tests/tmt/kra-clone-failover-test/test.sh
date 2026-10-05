#!/bin/bash
# Generated TMT port of .github/workflows/kra-clone-failover-test.yml
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
    docker rm -f ca client primarykra secondarykra 2>/dev/null || true
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

step "Set up CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=cads.example.com \
    --network=example \
    --network-alias=cads.example.com \
    --password=Secret.123 \
    cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=ca.example.com \
    --network=example \
    --network-alias=ca.example.com \
    ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_audit_signing_nickname= \
    -D pki_ds_url=ldap://cads.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update CA server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca dnf install -y xmlstarlet

# disable access log buffer
docker exec ca xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart CA server
docker exec ca pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update CA server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=client.example.com \
    --network=example \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import certs for client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec ca pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

# import CA signing cert
docker exec client pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C

# export admin cert and key
docker exec ca cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED/ca_admin_cert.p12

# import admin cert and key
docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import certs for client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin access to CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin access to CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary KRA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=primarykrads.example.com \
    --network=example \
    --network-alias=primarykrads.example.com \
    --password=Secret.123 \
    primarykrads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary KRA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primarykra.example.com \
    --network=example \
    --network-alias=primarykra.example.com \
    primarykra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca cp \
    /root/.dogtag/pki-tomcat/ca_admin.cert \
    $SHARED/ca_admin.cert

docker exec primarykra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_security_domain_uri=https://ca.example.com:8443 \
    -D pki_issuing_ca_uri=https://ca.example.com:8443 \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_audit_signing_nickname= \
    -D pki_admin_cert_file=$SHARED/ca_admin.cert \
    -D pki_ds_url=ldap://primarykrads.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update primary KRA server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primarykra dnf install -y xmlstarlet

# disable access log buffer
docker exec primarykra xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart primary KRA server
docker exec primarykra pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update primary KRA server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-connector-find | tee output

cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://primarykra.example.com:8443
  Nickname: subsystem
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import certs for client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export transport cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    ca-cert-transport-export \
    --output-file kra_transport.crt

# import transport cert
docker exec client pki nss-cert-import \
    --cert kra_transport.crt \
    kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import certs for client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin access to primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://primarykra.example.com:8443 \
    -n caadmin \
    kra-user-show \
    kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin access to primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate key and cert request
docker exec client pki \
    nss-cert-request \
    --type crmf \
    --subject UID=testuser1 \
    --transport kra_transport \
    --csr testuser1.csr

# issue cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caUserCert \
    --subject UID=testuser1 \
    --csr-file testuser1.csr \
    --output-file testuser1.crt

docker exec client openssl x509 \
    -text \
    -noout \
    -in testuser1.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check access logs in primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check HTTP methods, paths, protocols, status, and authenticated users
docker exec primarykra find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check access logs in primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary KRA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=secondarykrads.example.com \
    --network=example \
    --network-alias=secondarykrads.example.com \
    --password=Secret.123 \
    secondarykrads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary KRA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondarykra.example.com \
    --network=example \
    --network-alias=secondarykra.example.com \
    secondarykra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primarykra pki-server kra-clone-prepare \
    --pkcs12-file $SHARED/kra-certs.p12 \
    --pkcs12-password Secret.123

docker exec secondarykra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_security_domain_uri=https://ca.example.com:8443 \
    -D pki_issuing_ca_uri=https://ca.example.com:8443 \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_clone_pkcs12_path=$SHARED/kra-certs.p12 \
    -D pki_clone_pkcs12_password=Secret.123 \
    -D pki_clone_uri=https://primarykra.example.com:8443 \
    -D pki_audit_signing_nickname= \
    -D pki_admin_cert_file=$SHARED/ca_admin.cert \
    -D pki_ds_url=ldap://secondarykrads.example.com:3389 \
    -v

docker exec ca pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update secondary KRA server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondarykra dnf install -y xmlstarlet

# disable access log buffer
docker exec secondarykra xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart secondary KRA server
docker exec secondarykra pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update secondary KRA server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-connector-find | tee output

# KRA connector should have multiple KRAs
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://primarykra.example.com:8443 https://secondarykra.example.com:8443
  Nickname: subsystem
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check admin access to secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://secondarykra.example.com:8443 \
    -n caadmin \
    kra-user-show \
    kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check admin access to secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with multiple KRAs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# this test is currently failing due to this bug:
# https://bugzilla.redhat.com/show_bug.cgi?id=2363834
# TODO: update the test once the bug is fixed

# generate key and cert request
docker exec client pki \
    nss-cert-request \
    --type crmf \
    --subject UID=testuser2 \
    --transport kra_transport \
    --csr testuser2.csr

# issue cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caUserCert \
    --subject UID=testuser2 \
    --csr-file testuser2.csr \
    --output-file testuser2.crt \
    || true

# docker exec client openssl x509 \
#     -text \
#     -noout \
#     -in testuser2.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with multiple KRAs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check access logs in primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check HTTP methods, paths, protocols, status, and authenticated users
docker exec primarykra find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check access logs in primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Shut down primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primarykra pki-server stop --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Shut down primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with KRA failover"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# this test is currently failing due to this bug:
# https://bugzilla.redhat.com/show_bug.cgi?id=2363834
# TODO: update the test once the bug is fixed

# generate key and cert request
docker exec client pki \
    nss-cert-request \
    --type crmf \
    --subject UID=testuser3 \
    --transport kra_transport \
    --csr testuser3.csr

# issue cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caUserCert \
    --subject UID=testuser3 \
    --csr-file testuser3.csr \
    --output-file testuser3.crt \
    || true

# docker exec client openssl x509 \
#     -text \
#     -noout \
#     -in testuser3.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with KRA failover (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check access logs in secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check HTTP methods, paths, protocols, status, and authenticated users
docker exec secondarykra find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check access logs in secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primarykra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate key and cert request
docker exec client pki \
    nss-cert-request \
    --type crmf \
    --subject UID=testuser4 \
    --transport kra_transport \
    --csr testuser4.csr

# issue cert
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caUserCert \
    --subject UID=testuser4 \
    --csr-file testuser4.csr \
    --output-file testuser4.crt

docker exec client openssl x509 \
    -text \
    -noout \
    -in testuser4.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check access logs in secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check HTTP methods, paths, protocols, status, and authenticated users
docker exec secondarykra find /var/log/pki/pki-tomcat \
    -name "localhost_access_log.*" \
    -exec cat {} \; \
    | tail -5 \
    | sed -e 's/^.* .* \(.*\) \[.*\] "\(.*\)" \(.*\) .*$/\2 \3 \1/' \
    | tee output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check access logs in secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove secondary KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondarykra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca ls -l
docker exec ca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for primary KRA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec primarykra ls -l
docker exec primarykra find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for primary KRA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary KRA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primarykra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary KRA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary KRA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primarykra find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary KRA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primarykra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for secondary KRA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondarykra ls -l
docker exec secondarykra find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for secondary KRA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary KRA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondarykra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary KRA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary KRA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondarykra find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary KRA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondarykra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-clone-failover-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-clone-failover-test PASSED ===="
