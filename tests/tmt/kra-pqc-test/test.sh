#!/bin/bash
# Generated TMT port of .github/workflows/kra-pqc-test.yml
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

docker exec pki dnf install -y jq dumpasn1
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

step "Install CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-pqc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -la /root/.dogtag/pki-tomcat
docker exec pki cat /root/.dogtag/pki-tomcat/ca_admin.cert

docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert | tee output

# public key algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n 's/^ *Public Key Algorithm: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-pqc.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check transport unit config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server kra-config-find \
    | sed -n \
        -e '/^kra\.transportUnit\./p' \
    | sort \
    | tee output

cat > expected << EOF
kra.transportUnit.nickName=kra_transport
kra.transportUnit.signingAlgorithm=
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check transport unit config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check storage unit config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# ML-KEM wrapping (wrapping.2) should be configured
docker exec pki pki-server kra-config-find \
    | sed -n \
        -e '/^kra\.storageUnit\.wrapping\._/d' \
        -e '/^kra\.storageUnit\./p' \
    | sort \
    | tee output

cat > expected << EOF
kra.storageUnit.nickName=kra_storage
kra.storageUnit.wrapping.0.payloadEncryptionAlgorithm=DESede
kra.storageUnit.wrapping.0.payloadEncryptionIV=AQEBAQEBAQE=
kra.storageUnit.wrapping.0.payloadEncryptionMode=CBC
kra.storageUnit.wrapping.0.payloadEncryptionPadding=PKCS5Padding
kra.storageUnit.wrapping.0.payloadWrapAlgorithm=DES3/CBC/Pad
kra.storageUnit.wrapping.0.payloadWrapIV=AQEBAQEBAQE=
kra.storageUnit.wrapping.0.sessionKeyKeyGenAlgorithm=DESede
kra.storageUnit.wrapping.0.sessionKeyLength=168
kra.storageUnit.wrapping.0.sessionKeyType=DESede
kra.storageUnit.wrapping.0.sessionKeyWrapAlgorithm=RSA
kra.storageUnit.wrapping.1.payloadEncryptionAlgorithm=AES
kra.storageUnit.wrapping.1.payloadEncryptionIVLen=16
kra.storageUnit.wrapping.1.payloadEncryptionMode=CBC
kra.storageUnit.wrapping.1.payloadEncryptionPadding=PKCS5Padding
kra.storageUnit.wrapping.1.payloadWrapAlgorithm=AES KeyWrap/Padding
kra.storageUnit.wrapping.1.sessionKeyKeyGenAlgorithm=AES
kra.storageUnit.wrapping.1.sessionKeyLength=128
kra.storageUnit.wrapping.1.sessionKeyType=AES
kra.storageUnit.wrapping.1.sessionKeyWrapAlgorithm=RSA
kra.storageUnit.wrapping.2.payloadEncryptionAlgorithm=AES
kra.storageUnit.wrapping.2.payloadEncryptionIVLen=16
kra.storageUnit.wrapping.2.payloadEncryptionMode=CBC
kra.storageUnit.wrapping.2.payloadEncryptionPadding=PKCS5Padding
kra.storageUnit.wrapping.2.payloadWrapAlgorithm=AES KeyWrap/Padding
kra.storageUnit.wrapping.2.sessionKeyLength=256
kra.storageUnit.wrapping.2.sessionKeyType=AES
kra.storageUnit.wrapping.choice=2
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check storage unit config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKCS #12 encryption config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# PKCS #12 encryption should be configured
docker exec pki pki-server kra-config-find \
    | sed -n \
        -e '/^kra\.legacyPKCS12=/p' \
        -e '/^kra\.nonLegacyAlg=/p' \
    | sort \
    | tee output

cat > expected << EOF
kra.legacyPKCS12=false
kra.nonLegacyAlg=AES/None/PKCS5Padding/Kwp/256
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKCS #12 encryption config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server system certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server system certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server status | tee output

# CA should be a domain manager, but KRA should not
echo "True" > expected
echo "False" >> expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file kra_storage.crt \
    kra_storage

docker exec pki AtoB /var/lib/pki/pki-tomcat/conf/certs/kra_storage.csr kra_storage.der
docker exec pki dumpasn1 kra_storage.der

docker exec pki openssl x509 -text -noout -in kra_storage.crt | tee output

# public key algorithm should be "ML-KEM-768"
echo "ML-KEM-768" > expected
sed -n 's/^ *Public Key Algorithm: *\(.*\)$/\1/p' output > actual

diff expected actual

docker exec pki pki-server cert-validate kra_storage
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file kra_transport.crt \
    kra_transport

docker exec pki AtoB /var/lib/pki/pki-tomcat/conf/certs/kra_transport.csr kra_transport.der
docker exec pki dumpasn1 kra_transport.der

docker exec pki openssl x509 -text -noout -in kra_transport.crt | tee output

# public key algorithm should be "ML-KEM-768"
echo "ML-KEM-768" > expected
sed -n 's/^ *Public Key Algorithm: *\(.*\)$/\1/p' output > actual

diff expected actual

docker exec pki pki-server cert-validate kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file subsystem.crt \
    subsystem

docker exec pki openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr

docker exec pki openssl x509 -text -noout -in subsystem.crt | tee output

# public key algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n 's/^ *Public Key Algorithm: *\(.*\)$/\1/p' output > actual

diff expected actual

docker exec pki pki-server cert-validate subsystem
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
docker exec pki pki-server cert-export \
    --cert-file sslserver.crt \
    sslserver

docker exec pki openssl req -text -noout \
    -in /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr

docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# public key algorithm should be "ML-DSA-65"
echo "ML-DSA-65" > expected
sed -n 's/^ *Public Key Algorithm: *\(.*\)$/\1/p' output > actual

diff expected actual

docker exec pki pki-server cert-validate sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert after installing KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -la /root/.dogtag/pki-tomcat
docker exec pki cat /root/.dogtag/pki-tomcat/ca_admin.cert

docker exec pki openssl x509 -text -noout \
    -in /root/.dogtag/pki-tomcat/ca_admin.cert
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert after installing KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > expected << EOF
{
    "ArchivalMechanism": "keywrap",
    "EncryptionAlgorithm": "AES/CBC/PKCS5Padding",
    "KeyWrapAlgorithm": "AES KeyWrap/Padding",
    "RsaPublicKeyWrapAlgorithm": "RSA",
    "CaRsaPublicKeyWrapAlgorithm": "RSA",
    "Attributes": {
        "Attribute": []
    }
}
EOF

docker exec pki curl -ks https://pki.example.com:8443/ca/v2/info \
    | python -m json.tool \
    | tee actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > expected << EOF
{
    "ArchivalMechanism": "keywrap",
    "RecoveryMechanism": "keywrap",
    "EncryptionAlgorithm": "AES/CBC/PKCS5Padding",
    "WrapAlgorithm": "AES KeyWrap/Padding",
    "RsaPublicKeyWrapAlgorithm": "RSA",
    "Attributes": {
        "Attribute": []
    }
}
EOF

docker exec pki curl -ks https://pki.example.com:8443/kra/v2/info \
    | python -m json.tool \
    | tee actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA info (rc=$_rc)" >&2
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
    docker exec pki pki-healthcheck \
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
    echo "FAIL: Run PKI healthcheck (rc=$_rc)" >&2
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

step "Check KRA admin"
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
    --pkcs12-password Secret.123

docker exec pki pki nss-cert-verify \
    --cert-usage SSLClient \
    caadmin

docker exec pki pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TRANSPORT_CERT=$(docker exec pki openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec pki pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be configured
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=pki.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec pki pki-server ca-connector-find | tee output

# KRA connector should be configured
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://pki.example.com:8443
  Nickname: subsystem
EOF

diff expected output

# REST API should return KRA connector info
docker exec pki pki -n caadmin ca-kraconnector-show | tee output
sed -n 's/\s*Host:\s\+\(\S\+\):.*/\1/p' output > actual
echo pki.example.com > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-import \
    --cert kra_transport.crt \
    kra_transport
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial key requests"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-request-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/entries matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial key requests (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/key(s) matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert with ML-KEM key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create NSS database for CRMFPopClient
docker exec pki mkdir -p clnt-nssdb
docker exec pki bash -c "echo Secret.123 > clnt-nssdb/password.txt"
docker exec pki certutil -N -d clnt-nssdb -f clnt-nssdb/password.txt

# generate ML-KEM key and cert request with archival
docker exec pki CRMFPopClient \
    -d clnt-nssdb \
    -p Secret.123 \
    -n "cn=Test User,uid=testuser,ou=noPOP" \
    -q POP_NONE \
    -b kra_transport.crt \
    -a mlkem \
    -l 768 \
    -w "AES KeyWrap/Wrapped" \
    -v \
    -o $SHARED/testuser.csr

docker exec pki cat $SHARED/testuser.csr

# issue cert
docker exec pki pki \
    -u caadmin \
    -w Secret.123 \
    ca-cert-issue \
    --request-type crmf \
    --profile caMLKEMUserCert \
    --subject "cn=Test User,uid=testuser,ou=noPOP" \
    --csr-file $SHARED/testuser.csr \
    --output-file $SHARED/testuser.crt

docker exec pki cat $SHARED/testuser.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert with ML-KEM key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key requests after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-request-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/entries matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

# there should be 1 key request (ML-KEM enrollment)
cat > expected << EOF
  Type: enrollment
  Status: complete
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key requests after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check keys after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/key(s) matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

# there should be 1 ML-KEM key
cat > expected << EOF
  Algorithm: 2.16.840.1.101.3.4.4.2
  Size: 768
  Owner: UID=testuser,CN=Test User,OU=noPOP
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check keys after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify cert import into original NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Import the issued cert into clnt-nssdb (where the private key still exists)
docker exec pki pki -d clnt-nssdb -C clnt-nssdb/password.txt \
    nss-cert-import --cert $SHARED/testuser.crt testuser

# The cert should match the private key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec pki pki -d clnt-nssdb -C clnt-nssdb/password.txt \
    nss-cert-show testuser | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify cert import into original NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived ML-KEM key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find archived key by owner
docker exec pki pki \
    -n caadmin \
    kra-key-find \
    --owner "UID=testuser,CN=Test User,OU=noPOP" \
    | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"
echo $KEY_ID > cert.key_id

DEC_KEY_ID=$(python -c "print(int('$KEY_ID', 16))")
echo "Dec Key ID: $DEC_KEY_ID"

# get key record
docker exec ds ldapsearch \
    -H ldap://ds.example.com:3389 \
    -x \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b "cn=$DEC_KEY_ID,ou=keyRepository,ou=kra,dc=kra,dc=pki,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL | tee output

# Normalize LDAP output for validation
sed \
    -e '/^$/d' \
    -e 's/^\(serialno\): .*$/\1: XXXXX/' \
    -e 's/^\(privateKeyData\):: .*$/\1:: XXXXX/' \
    -e 's/^\(publicKeyData\):: .*$/\1:: XXXXX/' \
    -e 's/^\(metaInfo: payloadEncryptionIV\):.*/\1:XXXXX/' \
    -e 's/^\(dateOfCreate\): .*$/\1: XXXXX/' \
    -e 's/^\(dateOfModify\): .*$/\1: XXXXX/' \
    output > actual

cat > expected << EOF
dn: cn=$DEC_KEY_ID,ou=keyRepository,ou=kra,dc=kra,dc=pki,dc=example,dc=com
objectClass: top
objectClass: keyRecord
keyState: VALID
serialno: XXXXX
ownerName: UID=testuser,CN=Test User,OU=noPOP
keySize: 768
algorithm: 2.16.840.1.101.3.4.4.2
privateKeyData:: XXXXX
publicKeyData:: XXXXX
metaInfo: storageKeyAlgorithm:ML-KEM
metaInfo: payloadEncrypted:false
metaInfo: sessionKeyLength:256
metaInfo: payloadEncryptionPadding:PKCS5Padding
metaInfo: payloadEncryptionAlgorithm:AES
metaInfo: payloadEncryptionIV:XXXXX
metaInfo: payloadEncryptionMode:CBC
metaInfo: payloadWrapAlgorithm:AES KeyWrap/Padding
metaInfo: sessionKeyType:AES
dateOfCreate: XXXXX
dateOfModify: XXXXX
archivedBy: CA-pki.example.com-8443
cn: $DEC_KEY_ID
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check archived ML-KEM key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve ML-KEM key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat cert.key_id)
echo "Key ID: $KEY_ID"

# export cert into Base64-encoded format
BASE64_CERT=$(docker exec pki openssl x509 -in $SHARED/testuser.crt -outform DER | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

# create retrieval request with key ID, cert, and passphrase
docker exec pki bash -c "cat > $SHARED/request.json <<EOF
{
  \"ClassName\" : \"com.netscape.certsrv.key.KeyRecoveryRequest\",
  \"Attributes\" : {
    \"Attribute\" : [ {
      \"name\" : \"keyId\",
      \"value\" : \"$KEY_ID\"
    }, {
      \"name\" : \"certificate\",
      \"value\" : \"$BASE64_CERT\"
    }, {
      \"name\" : \"passphrase\",
      \"value\" : \"Secret.123\"
    } ]
  }
}
EOF
"

# retrieve archived ML-KEM key and cert into PKCS #12 file
# https://github.com/dogtagpki/pki/wiki/Retrieving-Archived-Key
docker exec pki pki \
    -n caadmin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --transport kra_transport \
    --output-data $SHARED/archived.p12

docker exec pki ls -l $SHARED/archived.p12
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve ML-KEM key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify archived ML-KEM PKCS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# Create a blank NSS database for recovery verification
docker exec pki mkdir -p recover-nssdb
docker exec pki bash -c "echo Secret.123 > recover-nssdb/password.txt"
docker exec pki certutil -N -d recover-nssdb -f recover-nssdb/password.txt

# Import the archived PKCS #12 file
docker exec pki pki \
    -d recover-nssdb \
    -C recover-nssdb/password.txt \
    pkcs12-import \
    --pkcs12 $SHARED/archived.p12 \
    --password Secret.123

# Remove recovered cert from NSS database
docker exec pki pki -d recover-nssdb -C recover-nssdb/password.txt \
    nss-cert-del "UID=testuser,CN=Test User,OU=noPOP"

# Import original cert into NSS database
docker exec pki pki -d recover-nssdb -C recover-nssdb/password.txt \
    nss-cert-import --cert $SHARED/testuser.crt testuser

# The original cert should match the recovered key (trust flags must be u,u,u)
echo "u,u,u" > expected
docker exec pki pki -d recover-nssdb -C recover-nssdb/password.txt \
    nss-cert-show testuser | tee output
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify archived ML-KEM PKCS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check key requests after retrieval"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-request-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/entries matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

# there should be 2 key requests (enrollment + recovery)
cat > expected << EOF
  Type: enrollment
  Status: complete

  Type: recovery
  Status: complete
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check key requests after retrieval (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check keys after retrieval"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    kra-key-find \
    | tee output

# normalize output
sed \
    -e '/-----/d' \
    -e '/key(s) matched/d' \
    -e '/Number of entries returned/d' \
    -e '/^ *Request ID:/d' \
    -e '/^ *Key ID:/d' \
    -e '/^ *Creation Time:/d' \
    -e '/^ *Modification Time:/d' \
    output > actual

# there should be 1 ML-KEM key
cat > expected << EOF
  Algorithm: 2.16.840.1.101.3.4.4.2
  Size: 768
  Owner: UID=testuser,CN=Test User,OU=noPOP
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check keys after retrieval (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy \
    -s KRA \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for warnings"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^WARNING:/p' stderr | tee output
diff /dev/null output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for warnings (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check external commands"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
sed -n '/^DEBUG: Command:/p' stderr | tee output
wc -l output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check external commands (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-pqc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-pqc-test PASSED ===="
