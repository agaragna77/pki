#!/bin/bash
# Generated TMT port of .github/workflows/kra-standalone-test.yml
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
    docker rm -f ca client kra 2>/dev/null || true
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

step "Install standalone CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_security_domain_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install standalone CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA certs into client"
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

# export CA admin cert and key
docker exec ca cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED/ca_admin_cert.p12

# import CA admin cert and key
docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA certs into client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check CA admin user
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-show \
    caadmin

# check CA admin roles
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-membership-find \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA security domain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-config-find | grep ^securitydomain. | sort | tee actual

# security domain should be disabled
diff /dev/null actual

docker exec client pki \
    -U https://ca.example.com:8443 \
    securitydomain-show \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# REST API should not return security domain info
echo "ResourceNotFoundException: Security domain not available" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA security domain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=kra.example.com \
    --network=example \
    --network-alias=kra.example.com \
    kra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install standalone KRA (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-standalone-step1.cfg \
    -s KRA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_storage_csr_path=${SHARED}/kra_storage.csr \
    -D pki_transport_csr_path=${SHARED}/kra_transport.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/kra_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/kra_admin.csr \
    -D pki_security_domain_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install standalone KRA (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA system and admin CSRs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in $SHARED/kra_storage.csr
docker exec client openssl req -text -noout -in $SHARED/kra_transport.csr
docker exec client openssl req -text -noout -in $SHARED/subsystem.csr
docker exec client openssl req -text -noout -in $SHARED/sslserver.csr
docker exec client openssl req -text -noout -in $SHARED/kra_audit_signing.csr
docker exec client openssl req -text -noout -in $SHARED/kra_admin.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA system and admin CSRs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA system and admin certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i client pki \
    -v \
    -U https://ca.example.com:8443 \
    -n caadmin \
    - << EOF

# issue KRA storage cert
ca-cert-issue \
    --profile caStorageCert \
    --csr-file $SHARED/kra_storage.csr \
    --output-file $SHARED/kra_storage.crt

# issue KRA transport cert
ca-cert-issue \
    --profile caTransportCert \
    --csr-file $SHARED/kra_transport.csr \
    --output-file $SHARED/kra_transport.crt

# issue subsystem cert
ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file $SHARED/subsystem.csr \
    --output-file $SHARED/subsystem.crt

# issue SSL server cert
ca-cert-issue \
    --profile caServerCert \
    --csr-file $SHARED/sslserver.csr \
    --output-file $SHARED/sslserver.crt

# issue KRA audit signing cert
ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file $SHARED/kra_audit_signing.csr \
    --output-file $SHARED/kra_audit_signing.crt

# issue KRA admin cert
ca-cert-issue \
    --profile AdminCert \
    --csr-file $SHARED/kra_admin.csr \
    --output-file $SHARED/kra_admin.crt
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA system and admin certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA system and admin certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl x509 -text -noout -in $SHARED/kra_storage.crt
docker exec client openssl x509 -text -noout -in $SHARED/kra_transport.crt
docker exec client openssl x509 -text -noout -in $SHARED/subsystem.crt
docker exec client openssl x509 -text -noout -in $SHARED/sslserver.crt
docker exec client openssl x509 -text -noout -in $SHARED/kra_audit_signing.crt
docker exec client openssl x509 -text -noout -in $SHARED/kra_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA system and admin certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# ensure KRA installation can complete without a running CA
docker exec ca pki-server stop --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install standalone KRA (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-standalone-step2.cfg \
    -s KRA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_storage_csr_path=${SHARED}/kra_storage.csr \
    -D pki_transport_csr_path=${SHARED}/kra_transport.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/kra_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/kra_admin.csr \
    -D pki_storage_cert_path=${SHARED}/kra_storage.crt \
    -D pki_transport_cert_path=${SHARED}/kra_transport.crt \
    -D pki_subsystem_cert_path=${SHARED}/subsystem.crt \
    -D pki_sslserver_cert_path=${SHARED}/sslserver.crt \
    -D pki_audit_signing_cert_path=${SHARED}/kra_audit_signing.crt \
    -D pki_admin_cert_path=${SHARED}/kra_admin.crt \
    -D pki_security_domain_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install standalone KRA (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server status | tee output

sed -n \
  -e '/^ *SD Manager:/p' \
  -e '/^ *SD Name:/p' \
  -e '/^ *SD Registration URL:/p' \
  output > actual

# security domain should be disabled
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA system certs (rc=$_rc)" >&2
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
    docker exec kra pki-healthcheck --failures-only
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

step "Start CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server start --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import KRA certs into client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import transport cert
docker exec client pki nss-cert-import \
    --cert $SHARED/kra_transport.crt \
    kra_transport

# export KRA admin cert and key
docker exec kra cp \
    /root/.dogtag/pki-tomcat/kra_admin_cert.p12 \
    $SHARED/kra_admin_cert.p12

# import KRA admin cert and key
docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/kra_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import KRA certs into client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check KRA admin user
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n kraadmin \
    kra-user-show \
    kraadmin

# check KRA admin roles
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n kraadmin \
    kra-user-membership-find \
    kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n kraadmin \
    kra-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA security domain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-config-find | grep ^securitydomain. | sort | tee actual

# security domain should be disabled
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA security domain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should not be configured
diff /dev/null output

# allow CA admin to manage KRA connector
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-user-membership-add \
    caadmin \
    "Enterprise KRA Administrators"

# KRA connector should not be configured
docker exec ca pki-server ca-connector-find | tee output
diff /dev/null output

# get KRA connector info via REST API
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-kraconnector-show \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# REST API should not return KRA connector info
echo "ConnectorNotFoundException: No KRA connectors" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment without KRA"
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
    --output-file testuser1.crt \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# operation should fail
echo "PKIException: Server Internal Error: KRA connector not configured" > expected
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment without KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA subsystem user in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA subsystem cert
docker exec ca pki-server cert-export \
    --cert-file $SHARED/ca_subsystem.crt \
    subsystem

# create CA subsystem user in KRA
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n kraadmin \
    kra-user-add \
    --full-name "CA" \
    --type agentType \
    --cert-file $SHARED/ca_subsystem.crt \
    CA

# allow CA to archive key in KRA
docker exec client pki \
    -U https://kra.example.com:8443 \
    -n kraadmin \
    kra-user-membership-add \
    CA \
    "Trusted Managers"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA subsystem user in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export transport cert
TRANSPORT_CERT=$(docker exec client pki nss-cert-export \
    --format DER \
    kra_transport \
    | base64 --wrap=0)

tee input.json << EOF
{
    "host": "kra.example.com",
    "port": "8443",
    "transportCert": "$TRANSPORT_CERT"
}
EOF

# add KRA connector
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-kraconnector-add \
    --input-file $SHARED/input.json

docker exec ca pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be configured
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=kra.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert enrollment with KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
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
    --output-file testuser2.crt

docker exec client openssl x509 \
    -text \
    -noout \
    -in testuser2.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment with KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA (rc=$_rc)" >&2
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

step "Check for client core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec client ls -l
docker exec client find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for client core dumps (rc=$_rc)" >&2
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

step "Check for KRA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra ls -l
docker exec kra find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for KRA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-standalone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-standalone-test PASSED ===="
