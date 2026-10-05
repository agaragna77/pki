#!/bin/bash
# Generated TMT port of .github/workflows/kra-external-certs-kryoptic-test.yml
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
    docker rm -f ca ds kra 2>/dev/null || true
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

step "Install Kryoptic"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# install OpenDNSSEC to ensure no conflicts
# https://github.com/dogtagpki/pki/issues/5045
docker exec ca dnf install -y kryoptic opensc opendnssec

docker exec ca rpm -ql kryoptic
docker exec ca cat /usr/share/p11-kit/modules/kryoptic.module

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec ca pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --show-info || true

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec ca pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots || true

# check with NSS
docker exec ca modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install Kryoptic (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file for HSM
echo "Secret.HSM" > password.hsm

# configure token
docker exec ca runuser -u pkiuser -- \
    mkdir -p /home/pkiuser/.config/kryoptic

docker exec -i ca runuser -u pkiuser -- \
    tee /home/pkiuser/.config/kryoptic/token.conf << EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/home/pkiuser/.config/kryoptic/token.sql"
objects_dedup = "TrustOnly"
EOF

# check with OpenSC
docker exec ca runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# initialize token and SO PIN
docker exec ca runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --label HSM \
    --so-pin $(cat password.hsm) \
    --init-token

# initialize user PIN
docker exec ca runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --login \
    --login-type so \
    --so-pin $(cat password.hsm) \
    --pin $(cat password.hsm) \
    --init-pin

# check with OpenSC
docker exec ca runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# check with NSS
docker exec ca runuser -u pkiuser -- \
    modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki \
    -d rootca \
    nss-cert-request \
    --subject "CN=Root CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/root-ca_signing.csr

docker exec ca pki \
    -d rootca \
    nss-cert-issue \
    --csr $SHARED/root-ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --cert $SHARED/root-ca_signing.crt

docker exec ca openssl x509 -text -noout -in $SHARED/root-ca_signing.crt

docker exec ca pki \
    -d rootca \
    nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install sub CA (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step1.cfg \
    -s CA \
    -D pki_cert_chain_nickname=root-ca_signing \
    -D pki_cert_chain_path=$SHARED/root-ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_ca_signing_csr_path=$SHARED/ca_signing.csr \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install sub CA (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue sub CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki \
    -d rootca \
    nss-cert-issue \
    --issuer root-ca_signing \
    --csr $SHARED/ca_signing.csr \
    --ext /usr/share/pki/server/certs/subca_signing.conf \
    --cert $SHARED/ca_signing.crt

docker exec ca openssl x509 -text -noout -in $SHARED/ca_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue sub CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install sub CA (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca-external-cert-step2.cfg \
    -s CA \
    -D pki_cert_chain_nickname=root-ca_signing \
    -D pki_cert_chain_path=$SHARED/root-ca_signing.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_ca_signing_csr_path=$SHARED/ca_signing.csr \
    -D pki_ca_signing_cert_path=$SHARED/ca_signing.crt \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install sub CA (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec ca pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    ca_signing

docker exec ca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123

docker exec ca pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=kra.example.com \
    --network=example \
    --network-alias=kra.example.com \
    kra
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA container (rc=$_rc)" >&2
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
docker exec kra dnf install -y kryoptic opensc opendnssec

docker exec kra rpm -ql kryoptic
docker exec kra cat /usr/share/p11-kit/modules/kryoptic.module

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec kra pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --show-info || true

# check with OpenSC
# NOTE: the command fails if there's no token
docker exec kra pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots || true

# check with NSS
docker exec kra modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install Kryoptic (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create KRA Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create password file for HSM
echo "Secret.HSM" > password.hsm

# configure token
docker exec kra runuser -u pkiuser -- \
    mkdir -p /home/pkiuser/.config/kryoptic

docker exec -i kra runuser -u pkiuser -- \
    tee /home/pkiuser/.config/kryoptic/token.conf << EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/home/pkiuser/.config/kryoptic/token.sql"
objects_dedup = "TrustOnly"
EOF

# check with OpenSC
docker exec kra runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# initialize token and SO PIN
docker exec kra runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --label HSM \
    --so-pin $(cat password.hsm) \
    --init-token

# initialize user PIN
docker exec kra runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --login \
    --login-type so \
    --so-pin $(cat password.hsm) \
    --pin $(cat password.hsm) \
    --init-pin

# check with OpenSC
docker exec kra runuser -u pkiuser -- \
    pkcs11-tool \
    --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    --list-slots

# check with NSS
docker exec kra runuser -u pkiuser -- \
    modutil -nocertdb -list
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create KRA Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA (step 1)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat root-ca_signing.crt ca_signing.crt > cert_chain.crt

docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-external-certs-step1.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/cert_chain.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_storage_csr_path=$SHARED/kra_storage.csr \
    -D pki_transport_csr_path=$SHARED/kra_transport.csr \
    -D pki_subsystem_csr_path=$SHARED/subsystem.csr \
    -D pki_sslserver_csr_path=$SHARED/sslserver.csr \
    -D pki_audit_signing_csr_path=$SHARED/kra_audit_signing.csr \
    -D pki_admin_csr_path=$SHARED/kra_admin.csr \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (step 1) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA storage cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in $SHARED/kra_storage.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caStorageCert \
    --csr-file $SHARED/kra_storage.csr \
    --output-file $SHARED/kra_storage.crt

docker exec ca openssl x509 -text -noout -in $SHARED/kra_storage.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA storage cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA transport cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in $SHARED/kra_transport.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caTransportCert \
    --csr-file $SHARED/kra_transport.csr \
    --output-file $SHARED/kra_transport.crt

docker exec ca openssl x509 -text -noout -in $SHARED/kra_transport.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA transport cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in $SHARED/subsystem.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caSubsystemCert \
    --csr-file $SHARED/subsystem.csr \
    --output-file $SHARED/subsystem.crt

docker exec ca openssl x509 -text -noout -in $SHARED/subsystem.crt
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
docker exec ca openssl req -text -noout -in $SHARED/sslserver.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file $SHARED/sslserver.csr \
    --output-file $SHARED/sslserver.crt

docker exec ca openssl x509 -text -noout -in $SHARED/sslserver.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue SSL server cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in $SHARED/kra_audit_signing.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile caAuditSigningCert \
    --csr-file $SHARED/kra_audit_signing.csr \
    --output-file $SHARED/kra_audit_signing.crt

docker exec ca openssl x509 -text -noout -in $SHARED/kra_audit_signing.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue KRA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca openssl req -text -noout -in $SHARED/kra_admin.csr

docker exec ca pki \
    -n caadmin \
    ca-cert-issue \
    --profile AdminCert \
    --csr-file $SHARED/kra_admin.csr \
    --output-file $SHARED/kra_admin.crt

docker exec ca openssl x509 -text -noout -in $SHARED/kra_admin.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue KRA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA (step 2)"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra-external-certs-step2.cfg \
    -s KRA \
    -D pki_cert_chain_path=$SHARED/cert_chain.crt \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_hsm_enable=True \
    -D pki_token_name=HSM \
    -D pki_token_password=Secret.HSM \
    -D pki_ca_signing_token=HSM \
    -D pki_ocsp_signing_token=HSM \
    -D pki_audit_signing_token=HSM \
    -D pki_subsystem_token=HSM \
    -D pki_sslserver_token=HSM \
    -D pki_storage_csr_path=$SHARED/kra_storage.csr \
    -D pki_transport_csr_path=$SHARED/kra_transport.csr \
    -D pki_subsystem_csr_path=$SHARED/subsystem.csr \
    -D pki_sslserver_csr_path=$SHARED/sslserver.csr \
    -D pki_audit_signing_csr_path=$SHARED/kra_audit_signing.csr \
    -D pki_admin_csr_path=$SHARED/kra_admin.csr \
    -D pki_storage_cert_path=$SHARED/kra_storage.crt \
    -D pki_transport_cert_path=$SHARED/kra_transport.crt \
    -D pki_subsystem_cert_path=$SHARED/subsystem.crt \
    -D pki_sslserver_cert_path=$SHARED/sslserver.crt \
    -D pki_audit_signing_cert_path=$SHARED/kra_audit_signing.crt \
    -D pki_admin_cert_path=$SHARED/kra_admin.crt \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)

docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA (step 2) (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-import \
    --cert $SHARED/root-ca_signing.crt \
    --trust CT,C,C \
    root-ca_signing

docker exec kra pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    ca_signing

docker exec kra pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/kra_admin_cert.p12 \
    --password Secret.123

docker exec kra pki nss-cert-find

docker exec kra pki -n kraadmin kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkidestroy -s KRA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra runuser -u pkiuser -- \
    rm -rf /home/pkiuser/.config/kryoptic
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove KRA Kryoptic token (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
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
docker exec ca rm -rf rootca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove CA Kryoptic token"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca runuser -u pkiuser -- \
    rm -rf /home/pkiuser/.config/kryoptic
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA Kryoptic token (rc=$_rc)" >&2
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

step "Check sub CA server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs/kra -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== kra-external-certs-kryoptic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-external-certs-kryoptic-test PASSED ===="
