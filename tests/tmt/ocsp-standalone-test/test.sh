#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-standalone-test.yml
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
    docker rm -f ca client ds ocsp 2>/dev/null || true
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
    --trust CT,C,C \
    ca_signing

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

step "Set up OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=ocsp.example.com \
    --network=example \
    --network-alias=ocsp.example.com \
    ocsp
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install standalone OCSP (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-standalone-step1.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_ocsp_signing_csr_path=${SHARED}/ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/ocsp_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/ocsp_admin.csr \
    -D pki_security_domain_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install standalone OCSP (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in ${SHARED}/ocsp_signing.csr

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caOCSPCert \
    --csr-file ${SHARED}/ocsp_signing.csr \
    --output-file ${SHARED}/ocsp_signing.crt

docker exec client openssl x509 -text -noout -in ${SHARED}/ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in ${SHARED}/subsystem.csr

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file ${SHARED}/subsystem.csr \
    --output-file ${SHARED}/subsystem.crt

docker exec client openssl x509 -text -noout -in ${SHARED}/subsystem.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in ${SHARED}/sslserver.csr

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file ${SHARED}/sslserver.csr \
    --output-file ${SHARED}/sslserver.crt

docker exec client openssl x509 -text -noout -in ${SHARED}/sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in ${SHARED}/ocsp_audit_signing.csr

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file ${SHARED}/ocsp_audit_signing.csr \
    --output-file ${SHARED}/ocsp_audit_signing.crt

docker exec client openssl x509 -text -noout -in ${SHARED}/ocsp_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client openssl req -text -noout -in ${SHARED}/ocsp_admin.csr

docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file ${SHARED}/ocsp_admin.csr \
    --output-file ${SHARED}/ocsp_admin.crt

docker exec client openssl x509 -text -noout -in ${SHARED}/ocsp_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server stop --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install standalone OCSP (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-standalone-step2.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_ocsp_signing_csr_path=${SHARED}/ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/ocsp_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/ocsp_admin.csr \
    -D pki_ocsp_signing_cert_path=${SHARED}/ocsp_signing.crt \
    -D pki_subsystem_cert_path=${SHARED}/subsystem.crt \
    -D pki_sslserver_cert_path=${SHARED}/sslserver.crt \
    -D pki_audit_signing_cert_path=${SHARED}/ocsp_audit_signing.crt \
    -D pki_admin_cert_path=${SHARED}/ocsp_admin.crt \
    -D pki_security_domain_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install standalone OCSP (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server status | tee output

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
    echo "FAIL: Check OCSP server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP system certs (rc=$_rc)" >&2
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
    docker exec ocsp pki-healthcheck --failures-only
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

step "Import OCSP certs into client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export OCSP admin cert and key
docker exec ocsp cp \
    /root/.dogtag/pki-tomcat/ocsp_admin_cert.p12 \
    $SHARED/ocsp_admin_cert.p12

# import OCSP admin cert and key
docker exec client pki pkcs12-import \
    --pkcs12 $SHARED/ocsp_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import OCSP certs into client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check OCSP admin user
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n ocspadmin \
    ocsp-user-show \
    ocspadmin

# check OCSP admin roles
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n ocspadmin \
    ocsp-user-membership-find \
    ocspadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n ocspadmin \
    ocsp-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP security domain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki-server ocsp-config-find | grep ^securitydomain. | sort | tee actual

# security domain should be disabled
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP security domain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL publishing in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-config-find > output

sed -n \
    -e '/^ca.publish.enable=/p' \
    -e '/^ca.publish.publisher.instance.OCSPPublisher-/p' \
    -e '/^ca.publish.rule.instance.ocsprule-/p' \
    output \
    | tee actual

# CRL publishing should not be configured
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL publishing in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert revocation without CRL publishing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert1 request
docker exec client pki \
    nss-cert-request \
    --subject "UID=testuser1" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser1.csr

# issue cert1
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser1.csr \
    --output-file testuser1.crt

# import cert1
docker exec client pki nss-cert-import \
    --cert testuser1.crt \
    testuser1

# get cert1 serial number
docker exec client pki nss-cert-show testuser1 | tee output
CERT1_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# revoke cert1
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-hold \
    --force \
    $CERT1_ID

sleep 5

# check cert1 status
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT1_ID | tee output

# cert1 should be unknown
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Unknown > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert revocation without CRL publishing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA subsystem user in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA subsystem cert
docker exec ca pki-server cert-export \
    --cert-file $SHARED/ca_subsystem.crt \
    subsystem

# create CA subsystem user in OCSP
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n ocspadmin \
    ocsp-user-add \
    --full-name "CA" \
    --type agentType \
    --cert-file $SHARED/ca_subsystem.crt \
    CA

# allow CA to publish CRL to OCSP
docker exec client pki \
    -U https://ocsp.example.com:8443 \
    -n ocspadmin \
    ocsp-user-membership-add \
    CA \
    "Trusted Managers"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA subsystem user in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CRL issuing point in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# convert CA signing cert into PKCS #7
docker exec ocsp pki pkcs7-cert-import \
    --input-file $SHARED/ca_signing.crt \
    --pkcs7 $SHARED/ca_signing.p7

# create CRL issuing point with the PKCS #7
docker exec ocsp pki-server ocsp-crl-issuingpoint-add \
    --cert-chain $SHARED/ca_signing.p7
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CRL issuing point in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure CRL publishing in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure OCSP publisher
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.enableClientAuth true
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.host ocsp.example.com
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.nickName subsystem
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.path /ocsp/agent/ocsp/addCRL
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.pluginName OCSPPublisher
docker exec ca pki-server ca-config-set ca.publish.publisher.instance.OCSPPublisher.port 8443

# configure CRL publishing rule
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.enable true
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.mapper NoMap
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.pluginName Rule
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.publisher OCSPPublisher
docker exec ca pki-server ca-config-set ca.publish.rule.instance.OCSPRule.type crl

# enable CRL publishing
docker exec ca pki-server ca-config-set ca.publish.enable true

# set buffer size to 0 so that revocation will take effect immediately
docker exec ca pki-server ca-config-set auths.revocationChecking.bufferSize 0

# update CRL immediately after each cert revocation
docker exec ca pki-server ca-config-set ca.crl.MasterCRL.alwaysUpdate true

docker exec ca pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure CRL publishing in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert revocation with CRL publishing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert2 request
docker exec client pki \
    nss-cert-request \
    --subject "UID=testuser2" \
    --ext /usr/share/pki/tools/examples/certs/testuser.conf \
    --csr testuser2.csr

# issue cert2
docker exec client pki \
    -U https://ca.example.com:8443 \
    -n caadmin \
    ca-cert-issue \
    --profile caUserCert \
    --csr-file testuser2.csr \
    --output-file testuser2.crt

# import cert2
docker exec client pki nss-cert-import \
    --cert testuser2.crt \
    testuser2

# get cert1 serial number
docker exec client pki nss-cert-show testuser1 | tee output
CERT1_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# get cert2 serial number
docker exec client pki nss-cert-show testuser2 | tee output
CERT2_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# revoke cert2
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u caadmin \
    -w Secret.123 \
    ca-cert-hold \
    --force \
    $CERT2_ID

sleep 5

# check cert2 status
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT1_ID | tee output

# cert1 should be revoked
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Revoked > expected
diff expected actual

# check cert2 status
docker exec client OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT2_ID | tee output

# cert2 should be revoked
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Revoked > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert revocation with CRL publishing (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP (rc=$_rc)" >&2
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

step "Check OCSP systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocsp find /var/lib/pki/pki-tomcat/logs/ocsp -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ocsp-standalone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-standalone-test PASSED ===="
