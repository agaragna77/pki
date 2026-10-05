#!/bin/bash
# Generated TMT port of .github/workflows/server-https-kryoptic-pqc-test.yml
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
    docker rm -f client pki 2>/dev/null || true
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
# Packages needed: xmlstarlet
# Most are available in the pki-runner container or Fedora host.
command -v xmlstarlet >/dev/null 2>&1 || dnf install -y xmlstarlet 2>/dev/null || true
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

step "Set up server container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=pki.example.com \
    --network=example \
    --network-alias=pki.example.com \
    --network-alias=server.example.com \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up server container (rc=$_rc)" >&2
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
    's/smime-key-exchange:ECDSA/smime-key-exchange:ML-DSA-65:ECDSA/' \
    /etc/crypto-policies/back-ends/nss.config
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable ML-DSA in default crypto-policies (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install Kryoptic"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# install OpenDNSSEC to ensure no conflicts
# https://github.com/dogtagpki/pki/issues/5045
docker exec pki dnf install -y kryoptic opensc opendnssec

docker exec pki rpm -ql kryoptic
docker exec pki cat /usr/share/p11-kit/modules/kryoptic.module

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec pki pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --show-info || true

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec pki pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots || true

# check with NSS
docker exec pki modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install Kryoptic (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file for HSM
echo "Secret.HSM" > password.hsm

# configure token
docker exec pki runuser -u pkiuser -- \
    mkdir -p /home/pkiuser/.config/kryoptic

docker exec -i pki runuser -u pkiuser -- \
    tee /home/pkiuser/.config/kryoptic/token.conf << EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/home/pkiuser/.config/kryoptic/token.sql"
objects_dedup = "TrustOnly"
EOF

# check with OpenSC
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# initialize token and SO PIN
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --label HSM \
    --so-pin $(cat password.hsm) \
    --init-token

# initialize user PIN
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --login \
    --login-type so \
    --so-pin $(cat password.hsm) \
    --pin $(cat password.hsm) \
    --init-pin

# check with OpenSC
docker exec pki runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# check with NSS
docker exec pki runuser -u pkiuser -- \
    modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Grant pkiuser access to shared directory"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki chmod 777 $SHARED
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Grant pkiuser access to shared directory (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create NSS database in PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file for internal token
echo "Secret.123" > password.txt

# create password config
echo "internal=$(cat password.txt)" > password.conf
echo "hardware-HSM=$(cat password.hsm)" >> password.conf

docker exec pki pki-server nss-create \
    --password-file $SHARED/password.txt

docker exec pki cp $SHARED/password.conf \
    /var/lib/pki/pki-tomcat/conf/password.conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create NSS database in PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate CA signing CSR in HSM
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    --token HSM \
    nss-cert-request \
    --key-type MLDSA \
    --key-strength 65 \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/ca_signing.csr

# create CA signing cert
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    --token HSM \
    nss-cert-issue \
    --csr $SHARED/ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --validity-length 1 \
    --validity-unit year \
    --cert $SHARED/ca_signing.crt

# check CA signing cert
openssl x509 -text -noout -in ca_signing.crt

# import CA signing cert
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    HSM:ca_signing

# check CA signing cert
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    nss-cert-show \
    HSM:ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# generate SSL server CSR in HSM
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    --token HSM \
    nss-cert-request \
    --key-type MLDSA \
    --key-strength 65 \
    --subject "CN=pki.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/sslserver.csr

# issue SSL server cert that expires in 2 minutes
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    --token HSM \
    nss-cert-issue \
    --issuer HSM:ca_signing \
    --csr $SHARED/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --validity-length 2 \
    --validity-unit minute \
    --cert $SHARED/sslserver.crt

# check SSL server cert
openssl x509 -text -noout -in sslserver.crt

# import SSL server cert
docker exec pki runuser -u pkiuser -- \
    pki \
    -d /var/lib/pki/pki-tomcat/alias \
    -f $SHARED/password.conf \
    nss-cert-import \
    --cert $SHARED/sslserver.crt \
    HSM:sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create HTTPS connector with Kryoptic HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server jss-enable
docker exec pki pki-server http-connector-add \
    --port 8443 \
    --scheme https \
    --secure true \
    --sslEnabled true \
    --sslProtocol SSL \
    --sslImpl org.dogtagpki.jss.tomcat.JSSImplementation \
    Secure
docker exec pki pki-server http-connector-cert-add \
    --keyAlias HSM:sslserver \
    --keystoreType pkcs11 \
    --keystoreProvider Mozilla-JSS
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create HTTPS connector with Kryoptic HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Deploy webapps"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server webapp-deploy \
    --descriptor /usr/share/pki/server/conf/Catalina/localhost/ROOT.xml \
    ROOT

docker exec pki pki-server webapp-deploy \
    --descriptor /usr/share/pki/server/conf/Catalina/localhost/pki.xml \
    pki
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Deploy webapps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server start
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start PKI server (rc=$_rc)" >&2
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
    --network-alias=client.example.com \
    client
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Wait for PKI server to start"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://pki.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Wait for PKI server to start (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with unknown issuer"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# run PKI CLI but don't trust the cert
echo n | docker exec -i client pki \
    -U https://pki.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://pki.example.com:8443
EOF

diff expected stdout

# check stderr
cat > expected << EOF
WARNING: UNKNOWN_ISSUER encountered on 'CN=pki.example.com' indicates an unknown CA cert 'CN=CA Signing Certificate'
Trust this certificate (y/N)? SEVERE: FATAL: SSL alert sent: UNKNOWN_CA
IOException: Unable to write to socket: Unable to validate CN=pki.example.com: Unknown issuer: CN=CA Signing Certificate
EOF

diff expected stderr

# the cert should not be stored
docker exec client pki nss-cert-find --subject CN=pki.example.com | tee output

diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with unknown issuer (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with unknown issuer with wrong hostname"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# run PKI CLI with wrong hostname
echo n | docker exec -i client pki \
    -U https://server.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://server.example.com:8443
EOF

diff expected stdout

# check stderr
cat > expected << EOF
WARNING: BAD_CERT_DOMAIN encountered on 'CN=pki.example.com' indicates a common-name mismatch
WARNING: UNKNOWN_ISSUER encountered on 'CN=pki.example.com' indicates an unknown CA cert 'CN=CA Signing Certificate'
Trust this certificate (y/N)? SEVERE: FATAL: SSL alert sent: ACCESS_DENIED
IOException: Unable to write to socket: Unable to validate CN=pki.example.com: Bad certificate domain: CN=pki.example.com
EOF

diff expected stderr

# the cert should not be stored
docker exec client pki nss-cert-find --subject CN=pki.example.com | tee output

diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with unknown issuer with wrong hostname (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with newly trusted server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
VERSION=$(
    xmlstarlet sel -t -v '/_:project/_:version' pom.xml \
    | sed 's/^\(.*\)-SNAPSHOT/\1/'
)

# run PKI CLI and trust the cert
echo y | docker exec -i client pki \
    -U https://pki.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://pki.example.com:8443
  Server Name: Dogtag Certificate System
  Server Version: $VERSION
EOF

diff expected stdout

# check stderr
cat > expected << EOF
WARNING: UNKNOWN_ISSUER encountered on 'CN=pki.example.com' indicates an unknown CA cert 'CN=CA Signing Certificate'
Trust this certificate (y/N)?
EOF

# remove trailing whitespace
sed -i 's/ *$//' stderr

# append end of line
echo >> stderr

diff expected stderr

# the cert should be stored and trusted
docker exec client pki nss-cert-find --subject CN=pki.example.com | tee output

sed -i \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output

cat > expected << EOF
  Nickname: CN=pki.example.com
  Subject DN: CN=pki.example.com
  Issuer DN: CN=CA Signing Certificate
  Trust Flags: P,,
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with newly trusted server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with trusted server cert with wrong hostname"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
VERSION=$(
    xmlstarlet sel -t -v '/_:project/_:version' pom.xml \
    | sed 's/^\(.*\)-SNAPSHOT/\1/'
)

# run PKI CLI with wrong hostname
docker exec client pki \
    -U https://server.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://server.example.com:8443
  Server Name: Dogtag Certificate System
  Server Version: $VERSION
EOF

diff expected stdout

# check stderr
cat > expected << EOF
WARNING: BAD_CERT_DOMAIN encountered on 'CN=pki.example.com' indicates a common-name mismatch
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with trusted server cert with wrong hostname (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with already trusted server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
VERSION=$(
    xmlstarlet sel -t -v '/_:project/_:version' pom.xml \
    | sed 's/^\(.*\)-SNAPSHOT/\1/'
)

# run PKI CLI with correct hostname
docker exec client pki \
    -U https://pki.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://pki.example.com:8443
  Server Name: Dogtag Certificate System
  Server Version: $VERSION
EOF

diff expected stdout

# check stderr
diff /dev/null stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with already trusted server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI CLI with expired server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
sleep 120

docker exec client pki \
    -U https://pki.example.com:8443 \
    info \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# check stdout
cat > expected << EOF
  Server URL: https://pki.example.com:8443
EOF

diff expected stdout

# check stderr
cat > expected << EOF
ERROR: EXPIRED_CERTIFICATE encountered on 'CN=pki.example.com' results in a denied SSL server cert!
SEVERE: FATAL: SSL alert sent: CERTIFICATE_EXPIRED
IOException: Unable to write to socket: Unable to validate CN=pki.example.com: Expired certificate: CN=pki.example.com
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI CLI with expired server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server stop --wait -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server remove -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki runuser -u pkiuser -- \
    rm -rf /home/pkiuser/.config/kryoptic
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== server-https-kryoptic-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== server-https-kryoptic-pqc-test PASSED ===="
