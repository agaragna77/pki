#!/bin/bash
# Generated TMT port of .github/workflows/subca-pqc-test.yml
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
    docker rm -f rootca rootcads subca subcads 2>/dev/null || true
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

step "Set up root CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=rootcads.example.com \
    --network=example \
    --network-alias=rootcads.example.com \
    --password=Secret.123 \
    rootcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up root CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=rootca.example.com \
    --network=example \
    --network-alias=rootca.example.com \
    rootca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Fedora version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
FEDORA_VERSION=$(docker exec rootca sed -n 's/^VERSION_ID=//p' /etc/os-release)
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

step "Set up root CA crypto-policies"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec rootca sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA crypto-policies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://rootcads.example.com:3389 \
    -D "pki_ca_signing_subject_dn=cn=Root CA Signing Certificate,o=EXAMPLE" \
    -v

docker exec rootca dnf install -y xmlstarlet

# disable access log buffer
docker exec rootca xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec rootca pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up sub CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=subcads.example.com \
    --network=example \
    --network-alias=subcads.example.com \
    --password=Secret.123 \
    subcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up sub CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up sub CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=subca.example.com \
    --network=example \
    --network-alias=subca.example.com \
    subca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up sub CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up sub CA crypto-policies"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 44 ]]; then
set +e
(
set -euo pipefail
docker exec subca sed -i \
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up sub CA crypto-policies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca pki-server cert-export \
    --cert-file $SHARED/root-ca_signing.crt \
    ca_signing

docker exec subca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/root-ca_signing.crt \
    -D pki_ds_url=ldap://subcads.example.com:3389 \
    -D pki_security_domain_hostname=rootca.example.com \
    -D pki_security_domain_user=caadmin \
    -D pki_security_domain_password=Secret.123 \
    -D pki_subordinate=True \
    -D pki_issuing_ca_hostname=rootca.example.com \
    -D "pki_ca_signing_subject_dn=cn=Sub CA Signing Certificate,o=EXAMPLE" \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca dnf install -y xmlstarlet

# disable access log buffer
docker exec subca xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec subca pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA signing cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_signing.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            Requested Extensions:
                X509v3 Basic Constraints: critical
                    CA:TRUE
                X509v3 Key Usage: critical
                    Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA signing cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA OCSP signing cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_ocsp_signing.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=CA OCSP Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA OCSP signing cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA audit signing cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_audit_signing.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=CA Audit Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA audit signing cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA subsystem cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=Subsystem Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA subsystem cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA SSL server cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=subca.example.com
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA SSL server cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA admin cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/ca_admin.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=EXAMPLE, OU=pki-tomcat, emailAddress=caadmin@example.com, CN=PKI Administrator
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec subca openssl x509 -text -noout \
    -in ca_signing.crt \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by root CA
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Root CA Signing Certificate
        Subject: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Subject Key Identifier:
            X509v3 Authority Key Identifier:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
            Authority Information Access:
                OCSP - URI:http://rootca.example.com:8080/ca/ocsp
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file ca_ocsp_signing.crt \
    ca_ocsp_signing

docker exec subca openssl x509 -text -noout \
    -in ca_ocsp_signing.crt \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by sub CA
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=CA OCSP Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://subca.example.com:8080/ca/ocsp
            X509v3 Extended Key Usage:
                OCSP Signing
            OCSP No Check:
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file ca_audit_signing.crt \
    ca_audit_signing

docker exec subca openssl x509 -text -noout \
    -in ca_audit_signing.crt \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by sub CA
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=CA Audit Signing Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            Authority Information Access:
                OCSP - URI:http://subca.example.com:8080/ca/ocsp
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file subsystem.crt \
    subsystem

docker exec subca openssl x509 -text -noout \
    -in subsystem.crt \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by root CA
# TODO: investigate inconsistent key usage
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Root CA Signing Certificate
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=Subsystem Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://rootca.example.com:8080/ca/ocsp
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file sslserver.crt \
    sslserver

docker exec subca openssl x509 -text -noout \
    -in sslserver.crt \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by sub CA
# TODO: investigate inconsistent key usage
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject: O=EXAMPLE, OU=pki-tomcat, CN=subca.example.com
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://subca.example.com:8080/ca/ocsp
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:subca.example.com
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl x509 -text -noout \
    -in /root/.dogtag/pki-tomcat/ca_admin.cert \
    | tee output

# normalize output
# - remove hex string
# - remove date and time
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Serial Number:$/d' \
    -e '/^ *Validity$/d' \
    -e '/^ *Not Before:/d' \
    -e '/^ *Not After :/d' \
    -e '/^ *pub:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

# cert should be issued by sub CA
# TODO: investigate inconsistent key usage
cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-65
        Issuer: O=EXAMPLE, CN=Sub CA Signing Certificate
        Subject: O=EXAMPLE, OU=pki-tomcat, emailAddress=caadmin@example.com, CN=PKI Administrator
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://subca.example.com:8080/ca/ocsp
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, E-mail Protection
    Signature Algorithm: ML-DSA-65
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run sub CA healthcheck"
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
    docker exec subca pki-healthcheck \
        --failures-only \
        --debug \
        > >(tee stdout) 2> >(tee stderr >&2)
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
    echo "FAIL: Run sub CA healthcheck (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec subca pki nss-cert-import \
    --cert ca_signing.crt \
    ca_signing

docker exec subca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123

docker exec subca pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA signing cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA signing cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA OCSP signing cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    -untrusted ca_signing.crt \
    ca_ocsp_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA OCSP signing cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA audit signing cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    -untrusted ca_signing.crt \
    ca_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA audit signing cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA subsystem cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    subsystem.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA subsystem cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA SSL server cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    -untrusted ca_signing.crt \
    sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA SSL server cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA admin cert chain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca openssl verify \
    -CAfile $SHARED/root-ca_signing.crt \
    -untrusted ca_signing.crt \
    /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin cert chain (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA signing cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-show ca_signing | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://rootca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer $SHARED/root-ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA signing cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA OCSP signing cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-show ca_ocsp_signing | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://subca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA OCSP signing cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA audit signing cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-show ca_audit_signing | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://subca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA audit signing cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA subsystem cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-show subsystem | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://rootca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer $SHARED/root-ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA subsystem cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA SSL server cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-show sslserver | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://subca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA SSL server cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA admin cert status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki nss-cert-show caadmin | tee output
SERIAL=$(sed -n "s/^\s*Serial Number:\s*\(\S*\)$/\1/p" output)

docker exec subca openssl ocsp \
    -url http://subca.example.com:8080/ca/ocsp \
    -CAfile $SHARED/root-ca_signing.crt \
    -issuer ca_signing.crt \
    -serial $SERIAL \
    | tee output

sed -n "/^$SERIAL:/p" output > actual
echo "$SERIAL: good" > expected

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin cert status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA signing cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as SSL CA (3)
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -u 3 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    ca_signing.crt \
    > >(tee stdout) 2> >(tee stderr >&2)

cat > expected << EOF
Root Certificate Subject:: "CN=Root CA Signing Certificate,O=EXAMPLE"
Certificate 1 Subject: "CN=Sub CA Signing Certificate,O=EXAMPLE"
EOF

diff expected stdout

cat > expected << EOF
Chain is good!
EOF

diff expected stderr

docker exec subca pki-server cert-validate ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA signing cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA OCSP signing cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as OCSP responder (10)
# TODO: investigate vfychain failure
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -u 10 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    ca_ocsp_signing.crt \
    > >(tee stdout) 2> >(tee stderr >&2) \
    || true

diff /dev/null stdout

cat > expected << EOF
Chain is bad!
PROBLEM WITH THE CERT CHAIN:
CERT 1. ca_signing [Certificate Authority]:
  ERROR -8180: Peer's Certificate has been revoked.
EOF

diff expected stderr

docker exec subca pki-server cert-validate ca_ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA OCSP signing cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA audit signing cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as Object signer (6)
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -u 6 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    ca_audit_signing.crt \
    > >(tee stdout) 2> >(tee stderr >&2)

cat > expected << EOF
Certificate 1 Subject: "CN=CA Audit Signing Certificate,OU=pki-tomcat,O=EXAMP
    LE"
EOF

diff expected stdout

cat > expected << EOF
Chain is good!
EOF

diff expected stderr

docker exec subca pki-server cert-show ca_audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA audit signing cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA subsystem cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as SSL client (0)
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -u 0 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    subsystem.crt \
    > >(tee stdout) 2> >(tee stderr >&2)

cat > expected << EOF
Root Certificate Subject:: "CN=Root CA Signing Certificate,O=EXAMPLE"
Certificate 1 Subject: "CN=Subsystem Certificate,OU=pki-tomcat,O=EXAMPLE"
EOF

diff expected stdout

cat > expected << EOF
Chain is good!
EOF

diff expected stderr

docker exec subca pki-server cert-validate subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA subsystem cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA SSL server cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as SSL server (1)
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -u 1 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    sslserver.crt \
    > >(tee stdout) 2> >(tee stderr >&2)

cat > expected << EOF
Root Certificate Subject:: "CN=Sub CA Signing Certificate,O=EXAMPLE"
Certificate 1 Subject: "CN=subca.example.com,OU=pki-tomcat,O=EXAMPLE"
EOF

diff expected stdout

cat > expected << EOF
Chain is good!
EOF

diff expected stderr

docker exec subca pki-server cert-validate sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA SSL server cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA admin cert usage"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# cert should be usable as SSL client (0)
docker exec subca /usr/lib64/nss/unsupported-tools/vfychain \
    -v \
    -d /root/.dogtag/nssdb \
    -u 0 \
    -pp \
    -g leaf \
    -h requireFreshInfo \
    -m ocsp \
    -s failIfNoInfo \
    -a \
    /root/.dogtag/pki-tomcat/ca_admin.cert \
    > >(tee stdout) 2> >(tee stderr >&2)

cat > expected << EOF
Root Certificate Subject:: "CN=Root CA Signing Certificate,O=EXAMPLE"
Certificate 1 Subject: "CN=PKI Administrator,E=caadmin@example.com,OU=pki-tom
    cat,O=EXAMPLE"
Certificate 2 Subject: "CN=Sub CA Signing Certificate,O=EXAMPLE"
EOF

diff expected stdout

cat > expected << EOF
Chain is good!
EOF

diff expected stderr

docker exec subca pki nss-cert-verify \
    --cert-usage SSLClient \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA admin cert usage (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootcads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs rootcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subcads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs subcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== subca-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== subca-pqc-test PASSED ===="
