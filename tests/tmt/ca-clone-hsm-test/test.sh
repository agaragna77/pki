#!/bin/bash
# Generated TMT port of .github/workflows/ca-clone-hsm-test.yml
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
    docker rm -f hsm primary secondary tertiary 2>/dev/null || true
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

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 5 certs
echo "5" > expected
docker exec primary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 4 certs
echo "4" > expected
docker exec primary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
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
# get CS.cfg from primary CA before cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary

# export CA signing cert
docker exec primary pki-server cert-export ca_signing \
    --cert-file ${SHARED}/ca_signing.crt

docker exec secondary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
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

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 3 certs
# NOTE: ideally it should match the
# primary CA, but it works fine as is
# TODO: investigate the discrepancy
echo "3" > expected
docker exec secondary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 4 certs
echo "4" > expected
docker exec secondary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in primary CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA after cloning
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after

# normalize expected result:
# - remove params that cannot be compared
# - set dbs.enableSerialManagement to true (automatically enabled when cloned)
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e 's/^\(dbs.enableSerialManagement\)=.*$/\1=true/' \
    CS.cfg.primary \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.primary.after \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in primary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary CA
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary

# normalize expected result:
# - remove params that cannot be compared
# - replace primary.example.com with secondary.example.com
# - replace primaryds.example.com with secondaryds.example.com
# - set ca.crl.MasterCRL.enableCRLCache to false (automatically disabled in the clone)
# - set ca.crl.MasterCRL.enableCRLUpdates to false (automatically disabled in the clone)
# - add params for the clone
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    -e 's/primary.example.com/secondary.example.com/' \
    -e 's/primaryds.example.com/secondaryds.example.com/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLCache\)=.*$/\1=false/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLUpdates\)=.*$/\1=false/' \
    -e '$ a ca.certStatusUpdateInterval=0' \
    -e '$ a ca.listenToCloneModifications=false' \
    -e '$ a master.ca.agent.host=primary.example.com' \
    -e '$ a master.ca.agent.port=8443' \
    CS.cfg.primary.after \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    CS.cfg.secondary \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up tertiary DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tertiaryds.example.com \
    --network=example \
    --network-alias=tertiaryds.example.com \
    --password=Secret.123 \
    tertiaryds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up tertiary DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=tertiary.example.com \
    --network=example \
    --network-alias=tertiary.example.com \
    tertiary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up SSH client in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary dnf install -y openssh-clients

# set up SSH client for root
docker exec tertiary mkdir -p /root/.ssh
docker exec tertiary chmod 700 /root/.ssh

docker cp id_ed25519 tertiary:/root/.ssh
docker exec tertiary chmod 600 /root/.ssh/id_ed25519

docker cp id_ed25519.pub tertiary:/root/.ssh

docker cp known_hosts tertiary:/root/.ssh

# check SSH client for root
docker exec tertiary \
    ssh \
    root@hsm.example.com \
    hostname

# set up SSH client for pkiuser
docker exec tertiary mkdir -p /home/pkiuser/.ssh
docker exec tertiary chmod 700 /home/pkiuser/.ssh
docker exec tertiary chown pkiuser:pkiuser /home/pkiuser/.ssh

docker cp id_ed25519 tertiary:/home/pkiuser/.ssh
docker exec tertiary chmod 600 /home/pkiuser/.ssh/id_ed25519
docker exec tertiary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519

docker cp id_ed25519.pub tertiary:/home/pkiuser/.ssh
docker exec tertiary chown pkiuser:pkiuser /home/pkiuser/.ssh/id_ed25519.pub

docker cp known_hosts tertiary:/home/pkiuser/.ssh

# enable login shell for pkiuser (needed by pkispawn)
docker exec tertiary usermod -s /bin/bash pkiuser

# check SSH client for pkiuser
docker exec tertiary sudo -i -u pkiuser \
    ssh \
    root@hsm.example.com \
    hostname
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up SSH client in tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up HSM client with p11-kit in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary dnf install -y p11-kit-server p11-kit-client

# register p11-kit-client module
docker exec -i tertiary tee /usr/share/p11-kit/modules/p11-kit-client.module << EOF
module: /usr/lib64/pkcs11/p11-kit-client.so
remote: |ssh root@hsm.example.com p11-kit remote /usr/lib64/pkcs11/libsofthsm2.so
EOF

# check registered PKCS #11 modules
docker exec tertiary sudo -i -u pkiuser p11-kit list-modules
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up HSM client with p11-kit in tertiary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# export CA signing CSR
docker exec secondary pki-server cert-export ca_signing \
    --csr-file ${SHARED}/ca_signing.csr

# export CA OCSP signing CSR
docker exec secondary pki-server cert-export ca_ocsp_signing \
    --csr-file ${SHARED}/ca_ocsp_signing.csr

# export CA audit signing CSR
docker exec secondary pki-server cert-export ca_audit_signing \
    --csr-file ${SHARED}/ca_audit_signing.csr

# export subsystem CSR
docker exec secondary pki-server cert-export subsystem \
    --csr-file ${SHARED}/subsystem.csr

docker exec tertiary pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-clone-of-clone.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_ds_url=ldap://tertiaryds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_hsm_modulename=p11-kit-client \
    -D pki_hsm_libfile=/usr/lib64/pkcs11/p11-kit-client.so \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ca_signing_csr_path=${SHARED}/ca_signing.csr \
    -D pki_ocsp_signing_token=HSM \
    -D pki_ocsp_signing_csr_path=${SHARED}/ca_ocsp_signing.csr \
    -D pki_audit_signing_token=HSM \
    -D pki_audit_signing_csr_path=${SHARED}/ca_audit_signing.csr \
    -D pki_subsystem_token=HSM \
    -D pki_subsystem_csr_path=${SHARED}/subsystem.csr \
    -D pki_sslserver_token=internal \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in tertiary PKI container (rc=$_rc)" >&2
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

step "Check system certs in internal token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 3 certs
# NOTE: ideally it should match the
# primary CA, but it works fine as is
# TODO: investigate the discrepancy
echo "3" > expected
docker exec tertiary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in internal token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system certs in HSM"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# there should be 4 certs
echo "4" > expected
docker exec tertiary pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    -f /var/lib/pki/pki-tomcat/conf/password.conf \
    --token HSM \
    nss-cert-find | tee output
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system certs in HSM (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in secondary CA after cloning"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary CA after cloning
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary.after

# normalize expected result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.secondary \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    CS.cfg.secondary.after \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in secondary CA after cloning (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CS.cfg in tertiary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from tertiary CA
docker cp tertiary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.tertiary

# normalize expected result:
# - remove params that cannot be compared
# - replace secondary.example.com with tertiary.example.com
# - replace secondaryds.example.com with tertiaryds.example.com
# - set master.ca.agent.host to secondary.example.com
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    -e 's/secondary.example.com/tertiary.example.com/' \
    -e 's/secondaryds.example.com/tertiaryds.example.com/' \
    -e 's/^\(master.ca.agent.host\)=.*$/\1=secondary.example.com/' \
    CS.cfg.secondary.after \
    | sort > expected

# normalize actual result:
# - remove params that cannot be compared
sed -e '/^installDate=/d' \
    -e '/^dbs.beginReplicaNumber=/d' \
    -e '/^dbs.endReplicaNumber=/d' \
    -e '/^dbs.nextBeginReplicaNumber=/d' \
    -e '/^dbs.nextEndReplicaNumber=/d' \
    -e '/^ca.sslserver.cert=/d' \
    -e '/^ca.sslserver.certreq=/d' \
    CS.cfg.tertiary \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CS.cfg in tertiary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from tertiary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tertiary pkidestroy \
    -s CA \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from tertiary PKI container (rc=$_rc)" >&2
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

step "Remove CA from secondary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from secondary PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA from primary PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA from primary PKI container (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-clone-hsm-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-clone-hsm-test PASSED ===="
