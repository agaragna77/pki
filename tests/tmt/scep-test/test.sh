#!/bin/bash
# Generated TMT port of .github/workflows/scep-test.yml
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
# Packages needed: podman-docker
# Most are available in the pki-runner container or Fedora host.
command -v podman-docker >/dev/null 2>&1 || dnf install -y podman-docker 2>/dev/null || true
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v

docker exec pki dnf install -y xmlstarlet

# disable access log buffer
docker exec pki xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

docker exec pki pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check default FlatFileAuth config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find \
    | sed -n \
        -e '/^auths\.impl\.FlatFileAuth\./p' \
        -e '/^auths\.instance\.flatFileAuth\./p' \
    | sort \
    | tee output

cat > expected << EOF
auths.impl.FlatFileAuth.class=com.netscape.cms.authentication.FlatFileAuth
auths.instance.flatFileAuth.fileName=/var/lib/pki/pki-tomcat/conf/ca/flatfile.txt
auths.instance.flatFileAuth.pluginName=FlatFileAuth
EOF

diff expected output

docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/flatfile.txt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check default FlatFileAuth config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check default SCEP responder config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find \
    | sed -n \
        -e '/^ca\.scep\._/d' \
        -e '/^ca\.scep\./p' \
    | sort \
    | tee output

cat > expected << EOF
ca.scep.allowedEncryptionAlgorithms=DES3
ca.scep.allowedHashAlgorithms=SHA256,SHA512
ca.scep.enable=false
ca.scep.encryptionAlgorithm=DES3
ca.scep.hashAlgorithm=SHA256
ca.scep.nonceSizeLimit=16
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check default SCEP responder config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable SCEP responder"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-set ca.scep.enable true
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable SCEP responder (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name client \
    --hostname client.example.com \
    --network example \
    --network-alias client.example.com \
    --detach \
    -it \
    quay.io/dogtagpki/sscep
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get client IP address"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(docker inspect -f '{{ .NetworkSettings.Networks.example.IPAddress }}' client)
echo "$CLIENT_IP" > client.ip
echo "Client IP: $CLIENT_IP"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get client IP address (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec -i pki tee /var/lib/pki/pki-tomcat/conf/ca/flatfile.txt << EOF
UID:$CLIENT_IP
PWD:Secret.123
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get CA certificate"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client sscep getca \
    -u http://pki.example.com:8080/ca/cgi-bin/pkiclient.exe \
    -c ca_signing.crt

docker exec client openssl x509 -text -noout -in ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get CA certificate (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client mkrequest -ip $CLIENT_IP Secret.123

docker exec client openssl req -text -noout -in local.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Modulus:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN=$CLIENT_IP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        Attributes:
            challengePassword        :Secret.123
            Requested Extensions:
                X509v3 Subject Alternative Name: critical
                    IP Address:$CLIENT_IP
    Signature Algorithm: sha256WithRSAEncryption
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert with DES3"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client sscep enroll \
    -u http://pki.example.com:8080/ca/cgi-bin/pkiclient.exe \
    -c ca_signing.crt \
    -k local.key \
    -r local.csr \
    -l 3des.crt \
    -E 3des \
    -S sha256
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert with DES3 (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check issued cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client openssl x509 -text -noout -in 3des.crt \
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
    -e '/^ *Modulus:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=EXAMPLE, OU=pki-tomcat, CN=CA Signing Certificate
        Subject: CN=$CLIENT_IP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://pki.example.com:8080/ca/ocsp
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, E-mail Protection
    Signature Algorithm: sha256WithRSAEncryption
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check issued cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client openssl pkcs12 \
    -export \
    -certfile ca_signing.crt \
    -inkey local.key \
    -in 3des.crt \
    -out 3des.p12 \
    -passout pass:Secret.123

docker cp client:3des.p12 .
docker cp 3des.p12 pki:.

docker exec pki pki \
    -d 3des \
    pkcs12-import \
    --pkcs12 3des.p12 \
    --password Secret.123

docker exec pki pki \
    -d 3des \
    nss-cert-show \
    $CLIENT_IP \
    | tee output

sed -n 's/^ *\(Trust Flags: .*\)$/\1/p' output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check client registration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/flatfile.txt \
    | tee output

# enrolled client should be commented out
cat > expected << EOF
#UID:$CLIENT_IP
#PWD:Secret.123
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client registration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure SCEP responder with AES"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-set ca.scep.encryptionAlgorithm AES 
docker exec pki pki-server ca-config-set ca.scep.allowedEncryptionAlgorithms AES

# restart CA subsystem
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure SCEP responder with AES (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register client"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec -i pki tee /var/lib/pki/pki-tomcat/conf/ca/flatfile.txt << EOF
UID:$CLIENT_IP
PWD:Secret.123
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register client (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client mkrequest -ip $CLIENT_IP Secret.123

docker exec client openssl req -text -noout -in local.csr \
    | tee output

# normalize output
# - remove hex string
sed -E \
    -e '/^ *[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+:?$/d' \
    -e '/^ *Modulus:$/d' \
    -e '/^ *Signature Value:$/d' \
    output > actual

cat > expected << EOF
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN=$CLIENT_IP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        Attributes:
            challengePassword        :Secret.123
            Requested Extensions:
                X509v3 Subject Alternative Name: critical
                    IP Address:$CLIENT_IP
    Signature Algorithm: sha256WithRSAEncryption
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert with AES"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client sscep enroll \
    -u http://pki.example.com:8080/ca/cgi-bin/pkiclient.exe \
    -c ca_signing.crt \
    -k local.key \
    -r local.csr \
    -l aes.crt \
    -E aes \
    -S sha256
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert with AES (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check issued cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client openssl x509 -text -noout -in aes.crt \
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
    -e '/^ *Modulus:$/d' \
    -e '/^ *Signature Value:$/d' \
    -e '/^$/d' \
    -e 's/ *$//' \
    output > actual

cat > expected << EOF
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=EXAMPLE, OU=pki-tomcat, CN=CA Signing Certificate
        Subject: CN=$CLIENT_IP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
            Authority Information Access:
                OCSP - URI:http://pki.example.com:8080/ca/ocsp
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, E-mail Protection
    Signature Algorithm: sha256WithRSAEncryption
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check issued cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check cert key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec client openssl pkcs12 \
    -export \
    -certfile ca_signing.crt \
    -inkey local.key \
    -in aes.crt \
    -out aes.p12 \
    -passout pass:Secret.123

docker cp client:aes.p12 .
docker cp aes.p12 pki:.

docker exec pki pki \
    -d aes \
    pkcs12-import \
    --pkcs12 aes.p12 \
    --password Secret.123

docker exec pki pki \
    -d aes \
    nss-cert-show \
    $CLIENT_IP \
    | tee output

sed -n 's/^ *\(Trust Flags: .*\)$/\1/p' output > actual

# the cert should match the key (trust flags must be u,u,u)
cat > expected << EOF
Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check client registration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
CLIENT_IP=$(cat client.ip)

docker exec pki cat /var/lib/pki/pki-tomcat/conf/ca/flatfile.txt \
    | tee output

# enrolled client should be commented out
cat > expected << EOF
#UID:$CLIENT_IP
#PWD:Secret.123
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client registration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from PKI container (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== scep-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== scep-test PASSED ===="
