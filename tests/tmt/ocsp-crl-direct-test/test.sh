#!/bin/bash
# Generated TMT port of .github/workflows/ocsp-crl-direct-test.yml
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
    docker rm -f ca cads ocsp ocspds 2>/dev/null || true
    docker volume rm ds-data 2>/dev/null || true
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
# Packages needed: libxml2-utils
# Most are available in the pki-runner container or Fedora host.
command -v libxml2-utils >/dev/null 2>&1 || dnf install -y libxml2-utils 2>/dev/null || true
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

step "Install CA in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://cads.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt

docker exec ca pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up OCSP DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=ocspds.example.com \
    --network=example \
    --network-alias=ocspds.example.com \
    --password=Secret.123 \
    ocspds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up OCSP DS container (rc=$_rc)" >&2
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

step "Install OCSP in OCSP container (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-standalone-step1.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ocspds.example.com:3389 \
    -D pki_ocsp_signing_csr_path=${SHARED}/ocsp_signing.csr \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_csr_path=${SHARED}/sslserver.csr \
    -D pki_audit_signing_csr_path=${SHARED}/ocsp_audit_signing.csr \
    -D pki_admin_csr_path=${SHARED}/ocsp_admin.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in OCSP container (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_signing.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caOCSPCert \
    --csr-file ${SHARED}/ocsp_signing.csr \
    --output-file ${SHARED}/ocsp_signing.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_signing.crt
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
docker exec ca openssl req -text -noout -in ${SHARED}/subsystem.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file ${SHARED}/subsystem.csr \
    --output-file ${SHARED}/subsystem.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/subsystem.crt
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
docker exec ca openssl req -text -noout -in ${SHARED}/sslserver.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file ${SHARED}/sslserver.csr \
    --output-file ${SHARED}/sslserver.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/sslserver.crt
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
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_audit_signing.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file ${SHARED}/ocsp_audit_signing.csr \
    --output-file ${SHARED}/ocsp_audit_signing.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_audit_signing.crt
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
docker exec ca openssl req -text -noout -in ${SHARED}/ocsp_admin.csr
docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file ${SHARED}/ocsp_admin.csr \
    --output-file ${SHARED}/ocsp_admin.crt
docker exec ca openssl x509 -text -noout -in ${SHARED}/ocsp_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue OCSP admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP in OCSP container (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkispawn \
    -f /usr/share/pki/server/examples/installation/ocsp-standalone-step2.cfg \
    -s OCSP \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://ocspds.example.com:3389 \
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
    -v

docker exec ocsp pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP in OCSP container (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install OCSP admin cert in OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec ocsp pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ocsp_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec ocsp pki -n ocspadmin ocsp-user-show ocspadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install OCSP admin cert in OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA user in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA subsystem cert
docker exec ca pki-server cert-export subsystem --cert-file ${SHARED}/subsystem.crt

# create CA user with CA subsystem cert
docker exec ocsp pki-server ocsp-user-add \
    --full-name "CA" \
    --type agentType \
    --cert ${SHARED}/subsystem.crt \
    CA

docker exec ocsp pki-server ocsp-group-member-add "Trusted Managers" CA
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA user in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CRL issuing point in OCSP"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# convert CA signing cert into PKCS #7 chain
docker exec ocsp pki pkcs7-cert-import --pkcs7 ca_signing.p7 --input-file ${SHARED}/ca_signing.crt
docker exec ocsp pki pkcs7-cert-find --pkcs7 ca_signing.p7

# create CRL issuing point with the PKCS #7 chain
docker exec ocsp pki-server ocsp-crl-issuingpoint-add --cert-chain ca_signing.p7
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CRL issuing point in OCSP (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure OCSP publishing in CA"
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
docker exec ca pki-server ca-crl-ip-mod -D alwaysUpdate=true MasterCRL

# restart CA subsystem
docker exec ca pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure OCSP publishing in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with no CRLs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CA agent and its cert
docker exec ca /usr/share/pki/tests/ca/bin/ca-agent-create.sh
docker exec ca /usr/share/pki/tests/ca/bin/ca-agent-cert-create.sh

# get cert serial number
docker exec ca pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# check cert status using OCSPClient
docker exec ocsp OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID \
    > >(tee stdout) 2> >(tee stderr >&2) || true

sed -n "/^SEVERE:/p" stderr > actual

# responder should fail since there's no CRLs
cat > expected << EOF
SEVERE: CLIException: OCSPResponseStatus: INTERNAL_ERROR
EOF

diff expected actual

# check cert status using OpenSSL
docker exec ocsp openssl ocsp \
    -url http://ocsp.example.com:8080/ocsp/ee/ocsp \
    -CAfile ${SHARED}/ca_signing.crt \
    -issuer ${SHARED}/ca_signing.crt \
    -serial $CERT_ID \
    | tee output

# responder should fail since there's no CRLs
cat > expected << EOF
Responder Error: internalerror (2)
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with no CRLs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with initial CRL"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get cert serial number
docker exec ca pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# force CRL update
docker exec ca pki -n caadmin ca-crl-update

# wait for CRL update
sleep 10

# check cert status using OCSPClient
docker exec ocsp OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# the status should be good
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Good > expected
diff expected actual

# check cert status using OpenSSL
docker exec ocsp openssl ocsp \
    -url http://ocsp.example.com:8080/ocsp/ee/ocsp \
    -CAfile ${SHARED}/ca_signing.crt \
    -issuer ${SHARED}/ca_signing.crt \
    -serial $CERT_ID | tee output

# the status should be good
sed -n "s/^$CERT_ID:\s*\(\S*\)$/\1/p" output > actual
echo good > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with initial CRL (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with revoked cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# revoke CA agent cert
docker exec ca /usr/share/pki/tests/ca/bin/ca-agent-cert-revoke.sh

# force CRL update
docker exec ca pki -n caadmin ca-crl-update

# wait for CRL update
sleep 10

# get cert serial number
docker exec ca pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# check cert status using OCSPClient
docker exec ocsp OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# the status should be revoked
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Revoked > expected
diff expected actual

# check cert status using OpenSSL
docker exec ocsp openssl ocsp \
    -url http://ocsp.example.com:8080/ocsp/ee/ocsp \
    -CAfile ${SHARED}/ca_signing.crt \
    -issuer ${SHARED}/ca_signing.crt \
    -serial $CERT_ID | tee output

# the status should be revoked
sed -n "s/^$CERT_ID:\s*\(\S*\)$/\1/p" output > actual
echo revoked > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with revoked cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP responder with unrevoked cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# unrevoke CA agent cert
docker exec ca /usr/share/pki/tests/ca/bin/ca-agent-cert-unrevoke.sh

# force CRL update
docker exec ca pki -n caadmin ca-crl-update

# wait for CRL update
sleep 10

# get cert serial number
docker exec ca pki nss-cert-show caagent | tee output
CERT_ID=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

# check cert status using OCSPClient
docker exec ocsp OCSPClient \
    -d /root/.dogtag/nssdb \
    -h ocsp.example.com \
    -p 8080 \
    -t /ocsp/ee/ocsp \
    -c ca_signing \
    --serial $CERT_ID | tee output

# the status should be good
sed -n "s/^CertStatus=\(.*\)$/\1/p" output > actual
echo Good > expected
diff expected actual

# check cert status using OpenSSL
docker exec ocsp openssl ocsp \
    -url http://ocsp.example.com:8080/ocsp/ee/ocsp \
    -CAfile ${SHARED}/ca_signing.crt \
    -issuer ${SHARED}/ca_signing.crt \
    -serial $CERT_ID | tee output

# the status should be good
sed -n "s/^$CERT_ID:\s*\(\S*\)$/\1/p" output > actual
echo good > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP responder with unrevoked cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove OCSP from OCSP container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ocsp pkidestroy -s OCSP -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove OCSP from OCSP container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec cads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS container logs (rc=$_rc)" >&2
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

step "Check OCSP DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ocspds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check OCSP DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ocspds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP DS container logs (rc=$_rc)" >&2
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
    echo "==== ocsp-crl-direct-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ocsp-crl-direct-test PASSED ===="
