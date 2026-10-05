#!/bin/bash
# Generated TMT port of .github/workflows/kra-rsa-oaep-test.yml
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
    docker rm -f ds pki 2>/dev/null || true
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
# Packages needed: dumpasn1
# Most are available in the pki-runner container or Fedora host.
command -v dumpasn1 >/dev/null 2>&1 || dnf install -y dumpasn1 2>/dev/null || true
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
    -D pki_use_oaep_rsa_keywrap=True \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check keywrap config in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-find \
    | sed -n \
        -e '/^keyWrap\./p' \
    | sort \
    | tee output

cat > expected << EOF
keyWrap.useOAEP=true
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check keywrap config in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_use_oaep_rsa_keywrap=True \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check keywrap config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server kra-config-find \
    | sed -n \
        -e '/^keyWrap\./p' \
    | sort \
    | tee output

cat > expected << EOF
keyWrap.useOAEP=true
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check keywrap config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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
kra.transportUnit.signingAlgorithm=SHA256withRSA
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
kra.storageUnit.wrapping.choice=1
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

step "Check KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file $SHARED/kra_transport.crt \
    kra_transport

docker exec pki AtoB \
    /var/lib/pki/pki-tomcat/conf/certs/kra_transport.csr \
    $SHARED/kra_transport.der

# ignore failure: Error: Object has zero length.
dumpasn1 kra_transport.der || true

openssl x509 -text -noout -in kra_transport.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector config in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TRANSPORT_CERT=$(docker exec pki openssl x509 \
    -in $SHARED/kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec pki pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector config in CA (rc=$_rc)" >&2
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
    "RsaPublicKeyWrapAlgorithm": "RSA_OAEP",
    "CaRsaPublicKeyWrapAlgorithm": "RSA_OAEP",
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
    "RsaPublicKeyWrapAlgorithm": "RSA_OAEP",
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

docker exec pki pki -n caadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Generate CSR"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-import \
    --cert $SHARED/kra_transport.crt \
    kra_transport

# generate CSR with AES KeyWrap/Wrapped and OAEP
docker exec pki CRMFPopClient \
    -d /root/.dogtag/nssdb \
    -p "" \
    -n "UID=testuser" \
    -b $SHARED/kra_transport.crt \
    -oaep \
    -v \
    -o $SHARED/testuser.csr

docker exec pki AtoB $SHARED/testuser.csr $SHARED/testuser.der

dumpasn1 testuser.der
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Generate CSR (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll cert with key archival"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --request-type crmf \
    --profile caDualCert \
    --subject "UID=testuser" \
    --csr-file $SHARED/testuser.csr \
    --output-file $SHARED/testuser.crt

openssl x509 -text -noout -in testuser.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll cert with key archival (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-import \
    --cert $SHARED/testuser.crt \
    testuser

# the cert should match the private key (trust flags must be u,u,u)
docker exec pki pki nss-cert-show testuser | tee output

echo "u,u,u" > expected
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check archived key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# find archived key by owner
docker exec pki pki \
    -n caadmin \
    kra-key-find \
    --owner "UID=testuser" \
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
ownerName: UID=testuser
keySize: 2048
algorithm: 1.2.840.113549.1.1.1
privateKeyData:: XXXXX
publicKeyData:: XXXXX
metaInfo: sessionKeyWrapAlgorithm:RSAES-OAEP
metaInfo: payloadEncrypted:false
metaInfo: sessionKeyKeyGenAlgorithm:AES
metaInfo: sessionKeyType:AES
metaInfo: sessionKeyLength:128
metaInfo: payloadEncryptionOID:2.16.840.1.101.3.4.1.2
metaInfo: payloadEncryptionIV:XXXXX
metaInfo: payloadWrapAlgorithm:AES KeyWrap/Padding
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
    echo "FAIL: Check archived key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Recover key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
KEY_ID=$(cat cert.key_id)
echo "Key ID: $KEY_ID"

# export cert into Base64-encoded format
BASE64_CERT=$(docker exec pki openssl x509 -in $SHARED/testuser.crt -outform DER | base64 --wrap=0)
echo "Cert: $BASE64_CERT"

# create recovery request with key ID, cert, and passphrase
cat > request.json << EOF
{
    "ClassName": "com.netscape.certsrv.key.KeyRecoveryRequest",
    "Attributes": {
        "Attribute": [
            {
                "name": "keyId",
                "value": "$KEY_ID"
            }, {
                "name": "certificate",
                "value": "$BASE64_CERT"
            }, {
                "name": "passphrase",
                "value": "Secret.123"
            }
        ]
    }
}
EOF

# retrieve archived key and cert into PKCS #12 file
docker exec pki pki \
    -n caadmin \
    kra-key-retrieve \
    --input $SHARED/request.json \
    --transport kra_transport \
    --output-data $SHARED/archived.p12
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Recover key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check recovered key"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# import recovered cert and key into new NSS database
docker exec pki pki \
    -d nssdb \
    pkcs12-import \
    --pkcs12 $SHARED/archived.p12 \
    --password Secret.123

# remove recovered cert from NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-del \
    "UID=testuser"

# import original cert into NSS database
docker exec pki pki \
    -d nssdb \
    nss-cert-import \
    --cert $SHARED/testuser.crt \
    testuser

# the original cert should match the recovered key (trust flags must be u,u,u)
docker exec pki pki \
    -d nssdb \
    nss-cert-show \
    testuser \
    | tee output

echo "u,u,u" > expected
sed -n "s/^\s*Trust Flags:\s*\(\S*\)$/\1/p" output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check recovered key (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s KRA -v
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
docker exec pki pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for PKI core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki ls -l
docker exec pki find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for PKI core dumps (rc=$_rc)" >&2
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
    echo "==== kra-rsa-oaep-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-rsa-oaep-test PASSED ===="
