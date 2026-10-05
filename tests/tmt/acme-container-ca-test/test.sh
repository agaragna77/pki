#!/bin/bash
# Generated TMT port of .github/workflows/acme-container-ca-test.yml
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

export DS_IMAGE="pki-runner"
export SHARED="/tmp/workdir/pki"

PKI_IMAGE="${PKI_IMAGE:-pki-runner}"

# Ensure docker and pki-runner are available
if ! command -v docker >/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

cleanup() {
    docker rm -f acme acmeds ca cads client 2>/dev/null || true
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

step "Retrieve ACME images"
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
    echo "FAIL: Retrieve ACME images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load ACME images"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker load from cache — images built locally by prepare
echo "Images already available (built by TMT prepare)"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Load ACME images (rc=$_rc)" >&2
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

step "Install dependencies in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y certbot
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install dependencies in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=cads.example.com \
    --network=example \
    --network-alias=cads.example.com \
    --password=Secret.123 \
    cads

docker exec cads dsconf \
    localhost \
    backend \
    config \
    get \
    | tee output

# CA DS backend should be LMDB
echo "nsslapd-backend-implement: mdb" > expected
cat output | sed -n "/^nsslapd-backend-implement:/p" > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA shared folders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir -p ca/certs
mkdir -p ca/conf
mkdir -p ca/logs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA shared folders (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --csr $SHARED/ca/certs/ca_signing.csr

docker exec client pki \
    nss-cert-issue \
    --csr $SHARED/ca/certs/ca_signing.csr \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    --validity-length 1 \
    --validity-unit year \
    --cert $SHARED/ca/certs/ca_signing.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ca/certs/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec client pki nss-cert-show ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert for CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=ca.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/ca/certs/sslserver.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/ca/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/ca/certs/sslserver.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ca/certs/sslserver.crt \
    ca_sslserver

docker exec client pki nss-cert-show ca_sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert for CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create OCSP signing cert for CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    nss-cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --csr $SHARED/ca/certs/ca_ocsp_signing.csr

docker exec client pki \
    nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/ca/certs/ca_ocsp_signing.csr \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    --cert $SHARED/ca/certs/ca_ocsp_signing.crt

docker exec client pki nss-cert-import \
    --cert $SHARED/ca/certs/ca_ocsp_signing.crt \
    ca_ocsp_signing

docker exec client pki nss-cert-show ca_ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create OCSP signing cert for CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export CA certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 > ca/certs/password

docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/ca/certs/server.p12 \
    --password-file $SHARED/ca/certs/password \
    ca_signing \
    ca_sslserver \
    ca_ocsp_signing

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/ca/certs/server.p12 \
    --password Secret.123 \
    --friendly-name sslserver \
    ca_sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/ca/certs/server.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export CA certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name ca \
    --hostname ca.example.com \
    --network example \
    --network-alias ca.example.com \
    -v $PWD/ca/certs:/certs \
    -v $PWD/ca/conf:/conf \
    -v $PWD/ca/logs:/logs \
    -e PKI_DS_URL=ldap://cads.example.com:3389 \
    -e PKI_DS_PASSWORD=Secret.123 \
    --detach \
    pki-ca

# wait for CA to start
docker exec client curl \
    --retry 180 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    https://ca.example.com:8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-db-init -v
docker exec ca pki-server ca-db-index-add -v

# LMDB indexes must be rebuilt
docker exec ca pki-server ca-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec client pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr $SHARED/admin.csr

# issue cert
docker exec client pki nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert $SHARED/admin.crt

# import cert
docker exec client pki nss-cert-import \
    --cert $SHARED/admin.crt \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create CA admin user
docker exec ca pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --password Secret.123 \
    admin

# set up CA admin roles
docker exec ca pki-server ca-user-role-add admin "Administrators"
docker exec ca pki-server ca-user-role-add admin "Certificate Manager Agents"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://ca.example.com:8443 \
    -u admin \
    -w Secret.123 \
    ca-user-show \
    admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up ACME DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=acmeds.example.com \
    --network=example \
    --network-alias=acmeds.example.com \
    --password=Secret.123 \
    acmeds

docker exec acmeds dsconf \
    localhost \
    backend \
    config \
    get \
    | tee output

# ACME DS backend should be LMDB
echo "nsslapd-backend-implement: mdb" > expected
cat output | sed -n "/^nsslapd-backend-implement:/p" > actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create ACME shared folders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
mkdir -p acme/certs
mkdir -p acme/metadata
mkdir -p acme/database
mkdir -p acme/issuer
mkdir -p acme/realm
mkdir -p acme/conf
mkdir -p acme/logs
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create ACME shared folders (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert for ACME"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create cert request
docker exec client pki nss-cert-request \
    --subject "CN=acme.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr $SHARED/acme/certs/sslserver.csr

# issue cert
docker exec client pki nss-cert-issue \
    --issuer ca_signing \
    --csr $SHARED/acme/certs/sslserver.csr \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --cert $SHARED/acme/certs/sslserver.crt

# import cert
docker exec client pki nss-cert-import \
    --cert $SHARED/acme/certs/sslserver.crt \
    acme_sslserver

docker exec client pki nss-cert-show acme_sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert for ACME (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export ACME certs and keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 > acme/certs/password

docker exec client pki pkcs12-export \
    --pkcs12 $SHARED/acme/certs/certs.p12 \
    --password-file $SHARED/acme/certs/password \
    acme_sslserver

docker exec client pki pkcs12-cert-mod \
    --pkcs12 $SHARED/acme/certs/certs.p12 \
    --password-file $SHARED/acme/certs/password \
    --friendly-name sslserver \
    acme_sslserver

docker exec client pki pkcs12-cert-find \
    --pkcs12 $SHARED/acme/certs/certs.p12 \
    --password-file $SHARED/acme/certs/password
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export ACME certs and keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure ACME database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "org.dogtagpki.acme.database.DSDatabase" > acme/database/class
echo "ldap://acmeds.example.com:3389" > acme/database/url
echo "BasicAuth" > acme/database/authType
echo "cn=Directory Manager" > acme/database/bindDN
echo "Secret.123" > acme/database/bindPassword
echo "dc=acme,dc=pki,dc=example,dc=com" > acme/database/baseDN
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure ACME database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure ACME issuer"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "org.dogtagpki.acme.issuer.PKIIssuer" > acme/issuer/class
echo "https://ca.example.com:8443" > acme/issuer/url
echo "acmeServerCert" > acme/issuer/profile
echo "admin" > acme/issuer/username
echo "Secret.123" > acme/issuer/password
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure ACME issuer (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure ACME realm"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "org.dogtagpki.acme.realm.DSRealm" > acme/realm/class
echo "ldap://acmeds.example.com:3389" > acme/realm/url
echo "BasicAuth" > acme/realm/authType
echo "cn=Directory Manager" > acme/realm/bindDN
echo "Secret.123" > acme/realm/bindPassword
echo "ou=people,dc=acme,dc=pki,dc=example,dc=com" > acme/realm/usersDN
echo "ou=groups,dc=acme,dc=pki,dc=example,dc=com" > acme/realm/groupsDN
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure ACME realm (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up ACME container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name acme \
    --hostname acme.example.com \
    --network example \
    --network-alias acme.example.com \
    -v $PWD/acme/certs:/certs \
    -v $PWD/acme/metadata:/metadata \
    -v $PWD/acme/database:/database \
    -v $PWD/acme/issuer:/issuer \
    -v $PWD/acme/realm:/realm \
    -v $PWD/acme/conf:/conf \
    -v $PWD/acme/logs:/logs \
    --detach \
    pki-acme

# wait for ACME to start
docker exec client curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    http://acme.example.com:8080/acme/directory
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up ACME container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki \
    -U https://acme.example.com:8443 \
    acme-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize ACME database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pki-server acme-database-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize ACME realm"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec acme pki-server acme-realm-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize ACME realm (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://acme.example.com:8080/acme/directory \
    --email user1@example.com \
    --agree-tos \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Register ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot certonly \
    --server http://acme.example.com:8080/acme/directory \
    -d client.example.com \
    --key-type rsa \
    --standalone \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enroll client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client ls -l /etc/letsencrypt/live/client.example.com
docker exec client cat /etc/letsencrypt/live/client.example.com/cert.pem

docker exec client openssl x509 \
    -text \
    -noout \
    -in /etc/letsencrypt/live/client.example.com/cert.pem

docker exec client pki nss-cert-verify \
    --cert /etc/letsencrypt/live/client.example.com/cert.pem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Renew client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot renew \
    --server http://acme.example.com:8080/acme/directory \
    --cert-name client.example.com \
    --force-renewal \
    --no-random-sleep-on-renew \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Renew client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot revoke \
    --server http://acme.example.com:8080/acme/directory \
    --cert-name client.example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Revoke client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot update_account \
    --server http://acme.example.com:8080/acme/directory \
    --email user2@example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot unregister \
    --server http://acme.example.com:8080/acme/directory \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs cads 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ca 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs acmeds 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs acme 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check client container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs client 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certbot logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec client cat /var/log/letsencrypt/letsencrypt.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certbot logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== acme-container-ca-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-container-ca-test PASSED ===="
