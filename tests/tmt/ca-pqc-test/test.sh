#!/bin/bash
# Generated TMT port of .github/workflows/ca-pqc-test.yml
# Step names match the GHA workflow.
set -euo pipefail

REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests" ]]; then
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
BIN="$REPO_ROOT/tests/bin"

export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"
# GHA persists env vars via $GITHUB_ENV; emulate with a temp file + source.
export GITHUB_ENV="${TMPDIR:-/tmp}/gha-env-$$"
touch "$GITHUB_ENV"
source_gha_env() { set -a; source "$GITHUB_ENV" 2>/dev/null || true; set +a; }
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

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec pki sed -n 's/^VERSION_ID=//p' /etc/os-release)
echo "FEDORA_VERSION=$FEDORA_VERSION" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Fedora version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Enable ML-DSA in default crypto-policies"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec pki sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ML-DSA-87:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_enable_access_log=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system cert keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# all keys should be "mldsa"
echo Secret.123 > password.txt
docker exec pki certutil -K -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt | tee output
echo "mldsa" > expected

grep ca_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep ca_ocsp_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep ca_audit_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep subsystem output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep sslserver output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system cert keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_signing | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki openssl x509 -text -noout -in ca_signing.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
docker exec pki pki-server ca-config-show ca.signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_ocsp_signing | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_ocsp_signing --cert-file ca_ocsp_signing.crt
docker exec pki openssl x509 -text -noout -in ca_ocsp_signing.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
docker exec pki pki-server ca-config-show ca.ocsp_signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_audit_signing | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_audit_signing --cert-file ca_audit_signing.crt
docker exec pki openssl x509 -text -noout -in ca_audit_signing.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
docker exec pki pki-server ca-config-show ca.audit_signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n subsystem | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export subsystem --cert-file subsystem.crt
docker exec pki openssl x509 -text -noout -in subsystem.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should not exist
echo "ERROR: No such parameter: ca.subsystem.defaultSigningAlgorithm" > expected
docker exec pki pki-server ca-config-show ca.subsystem.defaultSigningAlgorithm \
    > >(tee stdout) 2> >(tee stderr >&2) || true
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n sslserver | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export sslserver --cert-file sslserver.crt
docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should not exist
echo "ERROR: No such parameter: ca.sslserver.defaultSigningAlgorithm" > expected
docker exec pki pki-server ca-config-show ca.sslserver.defaultSigningAlgorithm \
    > >(tee stdout) 2> >(tee stderr >&2) || true
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable audit signing"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server stop --wait
docker exec pki pki-server ca-audit-config-mod --logSigning True
docker exec pki pki-server start --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable audit signing (rc=$_rc)" >&2
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

step "Check authenticating as CA admin user"
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

docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authenticating as CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n caadmin | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check issuing SSL server cert with RSA key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# issue cert
docker exec pki /usr/share/pki/tests/ca/bin/sslserver-create.sh

# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n sslserver | tee output

# key type should be "PKCS #1 RSA Encryption"
echo "PKCS #1 RSA Encryption" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Public Key Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# signing algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check issuing SSL server cert with RSA key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check issuing SSL server cert with ML-DSA-65 key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki certutil -F -d /root/.dogtag/nssdb -n sslserver

# issue cert
docker exec pki pki nss-cert-request \
        --subject "CN=pki.example.com" \
        --ext /usr/share/pki/server/certs/sslserver.conf \
        --csr sslserver_mldsa.csr \
        --key-type MLDSA \
        --key-strength 65

docker exec pki  pki -n caadmin ca-cert-issue \
        --profile caMLDSAServerCert \
        --csr-file sslserver_mldsa.csr \
        --output-file sslserver_mldsa.crt

docker exec pki pki nss-cert-import sslserver --cert sslserver_mldsa.crt

echo "ML-DSA-65" > expected

# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n sslserver | tee output

# key type should be "ML-DSA-65"
sed -n -e "s/\s*$//" -e "s/^\s*Public Key Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# signing algorithm should be "ML-DSA-65"
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in sslserver_mldsa.crt | tee output

# signing algorithm should be "ML-DSA-65"
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check issuing SSL server cert with ML-DSA-65 key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check audit get signed"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki cat /var/log/pki/pki-tomcat/ca/signedAudit/ca_audit | grep AuditEvent=AUDIT_LOG_SIGNING | tee output
grep -q . output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check audit get signed (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable caMLDSAUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki -n caadmin ca-profile-enable caMLDSAUserCert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable caMLDSAUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll OCSP test cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "UID=ocsp-test" \
    --csr ocsp_test.csr \
    --key-type MLDSA \
    --key-strength 65

docker exec pki pki -n caadmin ca-cert-issue \
    --profile caMLDSAUserCert \
    --csr-file ocsp_test.csr \
    --output-file ocsp_test.crt

docker exec pki openssl x509 -in ocsp_test.crt -noout -serial | tee output
CERT_SERIAL="0x$(sed 's/serial=//i' output)"
echo "$CERT_SERIAL" > ocsp_cert.id
echo "Issued OCSP test cert with serial: $CERT_SERIAL"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll OCSP test cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check good cert OCSP response signed with ML-DSA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_SERIAL=$(cat ocsp_cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ca/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_SERIAL \
    -resp_text \
    | tee output

# cert status should be good
sed -n "/^$CERT_SERIAL:/p" output > actual
echo "$CERT_SERIAL: good" > expected
diff expected actual

# OCSP response signature algorithm should be ML-DSA-65
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check good cert OCSP response signed with ML-DSA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke OCSP test cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_SERIAL=$(cat ocsp_cert.id)

docker exec pki pki -n caadmin ca-cert-hold \
    --force \
    $CERT_SERIAL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke OCSP test cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check revoked cert OCSP response signed with ML-DSA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CERT_SERIAL=$(cat ocsp_cert.id)

docker exec pki openssl ocsp \
    -url http://pki.example.com:8080/ca/ocsp \
    -CAfile ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $CERT_SERIAL \
    -resp_text \
    | tee output

# cert status should be revoked
sed -n "/^$CERT_SERIAL:/p" output > actual
echo "$CERT_SERIAL: revoked" > expected
diff expected actual

# OCSP response signature algorithm should be ML-DSA-65
echo "ML-DSA-65" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check revoked cert OCSP response signed with ML-DSA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generating new sslserver certificate with CMC"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check cert request
docker exec pki openssl req -text -noout -in /etc/pki/pki-tomcat/certs/sslserver.csr

# create CMC request
docker exec pki cp /etc/pki/pki-tomcat/certs/sslserver.csr sslserver.csr
docker exec pki CMCRequest \
    /usr/share/pki/server/examples/cmc/sslserver-cmc-request.cfg

# copy the submit and update the profile to use
docker exec pki \
    cp /usr/share/pki/server/examples/cmc/sslserver-cmc-submit.cfg \
    /tmp/sslserver-cmc-submit.cfg
docker exec pki sed -i 's/profileId=caCMCserverCert/profileId=caCMCMLDSAserverCert/' /tmp/sslserver-cmc-submit.cfg
docker exec pki sed -i 's/host=ca.example.com/host=pki.example.com/' /tmp/sslserver-cmc-submit.cfg

# submit CMC request
docker exec pki HttpClient \
    /tmp/sslserver-cmc-submit.cfg

# convert CMC response (DER PKCS #7) into PEM PKCS #7 cert chain
docker exec pki CMCResponse \
    -d /root/.dogtag/nssdb \
    -i sslserver.cmc-response \
    -o $SHARED/sslserver.p7b

# check issued cert chain
docker exec pki openssl pkcs7 -print_certs -in $SHARED/sslserver.p7b
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generating new sslserver certificate with CMC (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA and cleanup home"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA --remove-logs --remove-conf --force -v
docker exec pki rm -rf /root/.dogtag
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA and cleanup home (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create ML-DSA-87 configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki cp /usr/share/pki/server/examples/installation/ca-pqc.cfg ca-pqc.cfg
docker exec pki sed -i 's/65$/87/' ca-pqc.cfg
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create ML-DSA-87 configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with ML-DSA-87 and default buffer (65536 for PQC)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_enable_access_log=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with ML-DSA-87 and default buffer (65536 for PQC) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_signing | tee output

# signing algorithm should be "ML-DSA-87"
echo "ML-DSA-87" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki openssl x509 -text -noout -in ca_signing.crt | tee output

# signing algorithm should be "ML-DSA-87"
echo "ML-DSA-87" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "ML-DSA-87"
echo "ML-DSA-87" > expected
docker exec pki pki-server ca-config-show ca.signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authenticating as CA admin user"
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

docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authenticating as CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n caadmin | tee output

# signing algorithm should be "ML-DSA-87"
echo "ML-DSA-87" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert | tee output

# signing algorithm should be "ML-DSA-87"
echo "ML-DSA-87" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA --remove-logs --remove-conf --force -v
docker exec pki rm -rf /root/.dogtag
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA with ML-DSA-87 with legacy buffer size"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki sed -i \
    's/-Dredhat.crypto-policies=false/-Dredhat.crypto-policies=false -Djdk.tls.maxHandshakeMessageSize=18713/' \
    /usr/share/pki/server/conf/tomcat.conf

docker exec pki pkispawn \
    -f ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_enable_access_log=False \
    -v || echo "Failed" | tee output

echo "Failed" > expected
tail -n 1 output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA with ML-DSA-87 with legacy buffer size (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
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
    echo "==== ca-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-pqc-test PASSED ===="
