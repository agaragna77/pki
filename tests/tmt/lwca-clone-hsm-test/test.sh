#!/bin/bash
# Generated TMT port of .github/workflows/lwca-clone-hsm-test.yml
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
    docker rm -f hsm primary primaryds secondary secondaryds 2>/dev/null || true
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

step "Set up HSM container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=hsm.example.com \
    --network=example \
    --network-alias=hsm.example.com \
    hsm
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up HSM container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up SoftHSM in HSM container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec hsm dnf install -y softhsm

docker exec hsm softhsm2-util \
    --init-token \
    --label HSM \
    --so-pin Secret.HSM \
    --pin Secret.HSM \
    --free

docker exec hsm softhsm2-util --show-slots
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up SoftHSM in HSM container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up SSH server in HSM container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec hsm dnf install -y openssh-server openssh-clients

# remove default SSH server config to allow public key auth
docker exec hsm ls -l /etc/ssh/sshd_config.d
docker exec hsm rm -f /etc/ssh/sshd_config.d/40-redhat-crypto-policies.conf
docker exec hsm rm -f /etc/ssh/sshd_config.d/50-redhat.conf

# configure SSH server to allow root access with public key auth
docker exec hsm cat /etc/ssh/sshd_config
docker exec -i hsm tee /etc/ssh/sshd_config.d/root-login.conf << EOF
PermitRootLogin yes
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM yes
EOF

# start SSH server
docker exec hsm systemctl start sshd

# generate SSH client key
docker exec hsm ssh-keygen -f /root/.ssh/id_ed25519 -N ""
docker exec hsm cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys
docker exec hsm chmod 600 /root/.ssh/authorized_keys

# retrieve SSH client key
docker cp hsm:/root/.ssh/id_ed25519 .
docker cp hsm:/root/.ssh/id_ed25519.pub .

# retrieve SSH server key
docker exec hsm ssh-keyscan -H hsm.example.com \
    | tee known_hosts
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up SSH server in HSM container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=primaryds.example.com \
    --network=example \
    --network-alias=primaryds.example.com \
    --password=Secret.123 \
    primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=primary.example.com \
    --network=example \
    --network-alias=primary.example.com \
    primary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up SSH client in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary dnf install -y openssh-clients

# set up SSH client for root
docker exec primary mkdir -p /root/.ssh
docker exec primary chmod 700 /root/.ssh

docker cp id_ed25519 primary:/root/.ssh
docker exec primary chmod 600 /root/.ssh/id_ed25519

docker cp id_ed25519.pub primary:/root/.ssh

docker cp known_hosts primary:/root/.ssh

# check SSH client for root
docker exec primary \
    ssh \
    root@hsm.example.com \
    hostname

# set up SSH client for pkiuser
docker exec primary mkdir -p /home/pkiuser/.ssh
docker exec primary chmod 700 /home/pkiuser/.ssh
docker exec primary chown pkiuser:pkiuser /home/pkiuser/.ssh

docker cp id_ed25519 primary:/home/pkiuser/.ssh
docker exec primary chmod 600 /home/pkiuser/.ssh/id_ed25519
docker exec primary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519

docker cp id_ed25519.pub primary:/home/pkiuser/.ssh
docker exec primary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519.pub

docker cp known_hosts primary:/home/pkiuser/.ssh

# enable login shell for pkiuser (needed by pkispawn)
docker exec primary usermod -s /bin/bash pkiuser

# check SSH client for pkiuser
docker exec primary sudo -i -u pkiuser \
    ssh \
    root@hsm.example.com \
    hostname
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up SSH client in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up HSM client with p11-kit in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary dnf install -y p11-kit-server p11-kit-client

# register p11-kit-client module
docker exec -i primary tee /usr/share/p11-kit/modules/p11-kit-client.module << EOF
module: /usr/lib64/pkcs11/p11-kit-client.so
remote: |ssh root@hsm.example.com p11-kit remote /usr/lib64/pkcs11/libsofthsm2.so
EOF

# check registered PKCS #11 modules
docker exec primary sudo -i -u pkiuser p11-kit list-modules
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up HSM client with p11-kit in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://primaryds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_hsm_modulename=p11-kit-client \
    -D pki_hsm_libfile=/usr/lib64/pkcs11/p11-kit-client.so \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=internal \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert in primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file $SHARED/ca_signing.crt \
    ca_signing

docker exec primary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert in primary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 1 authority initially
echo "1" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual

diff expected actual

# it should be a host CA
echo "true" > expected
sed -n 's/^\s*Host authority:\s*\(.*\)$/\1/p' output > actual
diff expected actual

# store host CA ID
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > hostca-id
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=secondaryds.example.com \
    --network=example \
    --network-alias=secondaryds.example.com \
    --password=Secret.123 \
    secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=secondary.example.com \
    --network=example \
    --network-alias=secondary.example.com \
    secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up SSH client in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary dnf install -y openssh-clients

# set up SSH client for root
docker exec secondary mkdir -p /root/.ssh
docker exec secondary chmod 700 /root/.ssh

docker cp id_ed25519 secondary:/root/.ssh
docker exec secondary chmod 600 /root/.ssh/id_ed25519

docker cp id_ed25519.pub secondary:/root/.ssh

docker cp known_hosts secondary:/root/.ssh

# check SSH client for root
docker exec secondary \
    ssh \
    root@hsm.example.com \
    hostname

# set up SSH client for pkiuser
docker exec secondary mkdir -p /home/pkiuser/.ssh
docker exec secondary chmod 700 /home/pkiuser/.ssh
docker exec secondary chown pkiuser:pkiuser /home/pkiuser/.ssh

docker cp id_ed25519 secondary:/home/pkiuser/.ssh
docker exec secondary chmod 600 /home/pkiuser/.ssh/id_ed25519
docker exec secondary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519

docker cp id_ed25519.pub secondary:/home/pkiuser/.ssh
docker exec secondary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519.pub

docker cp known_hosts secondary:/home/pkiuser/.ssh

# enable login shell for pkiuser (needed by pkispawn)
docker exec secondary usermod -s /bin/bash pkiuser

# check SSH client for pkiuser
docker exec secondary sudo -i -u pkiuser \
    ssh \
    root@hsm.example.com \
    hostname
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up SSH client in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up HSM client with p11-kit in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary dnf install -y p11-kit-server p11-kit-client

# register p11-kit-client module
docker exec -i secondary tee /usr/share/p11-kit/modules/p11-kit-client.module << EOF
module: /usr/lib64/pkcs11/p11-kit-client.so
remote: |ssh root@hsm.example.com p11-kit remote /usr/lib64/pkcs11/libsofthsm2.so
EOF

# check registered PKCS #11 modules
docker exec secondary sudo -i -u pkiuser p11-kit list-modules
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up HSM client with p11-kit in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing cert
docker exec primary pki-server cert-export \
    --cert-file ${SHARED}/ca_signing.crt \
    ca_signing

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=$SHARED/ca_signing.crt \
    -D pki_ds_url=ldap://secondaryds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_hsm_modulename=p11-kit-client \
    -D pki_hsm_libfile=/usr/lib64/pkcs11/p11-kit-client.so \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=internal \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert in secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec primary cp \
    /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    $SHARED/ca_admin_cert.p12

docker exec secondary pki pkcs12-import \
    --pkcs12 $SHARED/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert in secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 1 authority initially
echo "1" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | wc -l > actual

diff expected actual

# it should be a host CA
echo "true" > expected
sed -n 's/^\s*Host authority:\s*\(.*\)$/\1/p' output > actual
diff expected actual

# check host CA ID
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > actual
diff hostca-id actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create LWCA in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

docker exec primary pki \
    -n caadmin \
    ca-authority-create \
    --parent $HOSTCA_ID \
    CN=LWCA \
    | tee output

# store LWCA ID
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > lwca-id
LWCA_ID=$(cat lwca-id)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create LWCA in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)
LWCA_ID=$(cat lwca-id)

docker exec primary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 2 authorities
echo -e "$HOSTCA_ID\n$LWCA_ID" | sort > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)
LWCA_ID=$(cat lwca-id)

docker exec secondary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 2 authorities
echo -e "$HOSTCA_ID\n$LWCA_ID" | sort > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output | sort > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll with LWCA in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
LWCA_ID=$(cat lwca-id)

# get LWCA's DN
docker exec primary pki \
    -n caadmin \
    ca-authority-show \
    $LWCA_ID \
    | tee output
LWCA_DN=$(sed -n -e 's/^\s*Authority DN:\s*\(.*\)$/\1/p' output)

# submit enrollment request against LWCA
docker exec primary pki \
    client-cert-request \
    --issuer-id $LWCA_ID \
    UID=testuser | tee output
REQUEST_ID=$(sed -n -e 's/^\s*Request ID:\s*\(.*\)$/\1/p' output)

# approve request
docker exec primary pki \
    -n caadmin \
    ca-cert-request-approve \
    $REQUEST_ID \
    --force \
    | tee output
CERT_ID=$(sed -n -e 's/^\s*Certificate ID:\s*\(.*\)$/\1/p' output)

docker exec primary pki ca-cert-show $CERT_ID | tee output

# check issuer DN
echo "$LWCA_DN" > expected
sed -n -e 's/^\s*Issuer DN:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll with LWCA in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll with LWCA in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
LWCA_ID=$(cat lwca-id)

# get LWCA's DN
docker exec secondary pki \
    -n caadmin \
    ca-authority-show \
    $LWCA_ID \
    | tee output
LWCA_DN=$(sed -n -e 's/^\s*Authority DN:\s*\(.*\)$/\1/p' output)

# submit enrollment request against LWCA
docker exec secondary pki \
    client-cert-request \
    --issuer-id $LWCA_ID \
    UID=testuser | tee output
REQUEST_ID=$(sed -n -e 's/^\s*Request ID:\s*\(.*\)$/\1/p' output)

# approve request
docker exec secondary pki \
    -n caadmin \
    ca-cert-request-approve \
    $REQUEST_ID \
    --force \
    | tee output
CERT_ID=$(sed -n -e 's/^\s*Certificate ID:\s*\(.*\)$/\1/p' output)

docker exec secondary pki ca-cert-show $CERT_ID | tee output

# check issuer DN
echo "$LWCA_DN" > expected
sed -n -e 's/^\s*Issuer DN:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll with LWCA in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove LWCA from secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
LWCA_ID=$(cat lwca-id)

# disable LWCA
docker exec secondary pki \
    -n caadmin \
    ca-authority-disable \
    $LWCA_ID

# remove LWCA
docker exec secondary pki \
    -n caadmin \
    ca-authority-del \
    --force \
    $LWCA_ID
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove LWCA from secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

docker exec secondary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 1 authority
echo "$HOSTCA_ID" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check authorities in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
HOSTCA_ID=$(cat hostca-id)

docker exec primary pki \
    -n caadmin \
    ca-authority-find \
    | tee output

# there should be 1 authority
echo "$HOSTCA_ID" > expected
sed -n 's/^\s*ID:\s*\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check authorities in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSH systemd journal in HSM container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec hsm journalctl -x --no-pager -u sshd.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSH systemd journal in HSM container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs primaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check primary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondaryds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs secondaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary PKI server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary PKI server access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check secondary CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== lwca-clone-hsm-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== lwca-clone-hsm-test PASSED ===="
