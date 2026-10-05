#!/bin/bash
# Generated TMT port of .github/workflows/server-https-pkcs12-test.yml
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

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CA signing cert in ca_signing.p12
docker exec pki keytool \
    -genkeypair \
    -keystore $SHARED/ca_signing.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias ca_signing \
    -dname "CN=CA Signing Certificate" \
    -ext BasicConstraints:critical=ca:true \
    -ext KeyUsage:critical=digitalSignature,nonRepudiation,keyCertSign,cRLSign \
    -keyalg RSA \
    -keypass Secret.123

# check keys in ca_signing.p12
docker exec pki pki pkcs12-key-find \
    --pkcs12-file $SHARED/ca_signing.p12 \
    --pkcs12-password Secret.123

# check certs in ca_signing.p12
docker exec pki pki pkcs12-cert-find \
    --pkcs12-file $SHARED/ca_signing.p12 \
    --pkcs12-password Secret.123

# export CA signing cert
docker exec pki keytool \
    -exportcert \
    -keystore $SHARED/ca_signing.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias ca_signing \
    -rfc \
    -file $SHARED/ca_signing.crt

# check CA signing cert
openssl x509 -text -noout -in ca_signing.crt
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
# generate SSL server key in keystore.p12
docker exec pki keytool \
    -genkeypair \
    -keystore /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias sslserver \
    -dname "CN=pki.example.com" \
    -keyalg RSA \
    -keypass Secret.123

# check keys in keystore.p12
docker exec pki pki pkcs12-key-find \
    --pkcs12-file /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    --pkcs12-password Secret.123

# check certs in keystore.p12
docker exec pki pki pkcs12-cert-find \
    --pkcs12-file /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    --pkcs12-password Secret.123

# create SSL server cert request
docker exec pki keytool \
    -certreq \
    -keystore /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias sslserver \
    -file $SHARED/sslserver.csr

# issue SSL server cert that expires in 2 minutes
docker exec pki keytool \
    -gencert \
    -keystore $SHARED/ca_signing.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias ca_signing \
    -startdate -1d+2M \
    -validity 1 \
    -ext BasicConstraints:critical=ca:false \
    -ext KeyUsage:critical=digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth \
    -ext SubjectAlternativeName=DNS:pki.example.com \
    -rfc \
    -infile $SHARED/sslserver.csr \
    -outfile $SHARED/sslserver.crt

# check SSL server cert
openssl x509 -text -noout -in sslserver.crt

# create SSL server cert chain
cat ca_signing.crt sslserver.crt > sslserver.chain

# import SSL server cert chain into keystore.p12
docker exec pki keytool \
    -importcert \
    -keystore /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    -storetype pkcs12 \
    -storepass Secret.123 \
    -alias sslserver \
    -file $SHARED/sslserver.chain \
    -noprompt

# configure keystore.p12 owner and permissions
docker exec pki chown pkiuser:pkiuser /var/lib/pki/pki-tomcat/conf/keystore.p12
docker exec pki chmod 660 /var/lib/pki/pki-tomcat/conf/keystore.p12
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create HTTPS connector with PKCS #12 file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server http-connector-add \
    --port 8443 \
    --scheme https \
    --secure true \
    --sslEnabled true \
    --sslProtocol SSL \
    Secure
docker exec pki pki-server http-connector-cert-add \
    --keyAlias sslserver \
    --keystoreType pkcs12 \
    --keystoreFile /var/lib/pki/pki-tomcat/conf/keystore.p12 \
    --keystorePassword Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create HTTPS connector with PKCS #12 file (rc=$_rc)" >&2
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

step "Check PKI CLI with unknown issuer and wrong hostname"
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
    echo "FAIL: Check PKI CLI with unknown issuer and wrong hostname (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== server-https-pkcs12-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== server-https-pkcs12-test PASSED ===="
