#!/bin/bash
# Generated TMT port of .github/workflows/acme-postgresql-test.yml
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
    docker rm -f client ds pki postgresql 2>/dev/null || true
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

step "Install CA in PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial CA certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# there should be 6 certs
echo "6" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create postgresql certificates"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "CN=postgresql.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr

docker exec pki pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file sslserver.csr \
    --subject "CN=postgresql.example.com" \
    --output-file sslserver.crt

docker exec pki pki nss-cert-import \
    --cert sslserver.crt \
    postgresql

docker exec pki pk12util -o sslserver.p12 -n postgresql -d /root/.dogtag/nssdb -W secret
docker cp pki:sslserver.p12 .
openssl pkcs12 -in sslserver.p12 -nocerts -out sslserver.key -noenc -password  pass:secret
openssl pkcs12 -in sslserver.p12 -nokeys -clcerts -out sslserver.crt  -password pass:secret
openssl pkcs12 -in sslserver.p12 -nokeys -cacerts -out ca.crt  -password pass:secret
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create postgresql certificates (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create postgresql Docker file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat > Dockerfile-Postgresql <<EOF
FROM postgres AS postgres-ssl

# Copy certificates
COPY sslserver.key /var/lib/postgresql/server.key
COPY sslserver.crt /var/lib/postgresql/server.crt
RUN chown postgres:postgres /var/lib/postgresql/server.crt && \
chown postgres:postgres /var/lib/postgresql/server.key && \
chmod 600 /var/lib/postgresql/server.key
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create postgresql Docker file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Build postgrsql image with certificates"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: docker/build-push-action — translated to docker build
docker build -f Dockerfile-Postgresql -t postgres-ssl .
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Build postgrsql image with certificates (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Deploy postgresql"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker run \
    --name postgresql \
    --hostname postgresql.example.com \
    --network example \
    --network-alias postgresql.example.com \
    -e POSTGRES_PASSWORD=mysecretpassword \
    -e POSTGRES_USER=acme \
    --detach \
    postgres-ssl \
    -c ssl=on \
    -c ssl_cert_file=/var/lib/postgresql/server.crt \
    -c ssl_key_file=/var/lib/postgresql/server.key
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Deploy postgresql (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up database drivers"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y postgresql-jdbc
docker exec pki ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib
docker exec pki ln -s /usr/share/java/ongres-scram/scram-client.jar /usr/share/pki/server/common/lib
docker exec pki ln -s /usr/share/java/ongres-scram/scram-common.jar /usr/share/pki/server/common/lib
docker exec pki ln -s /usr/share/java/ongres-stringprep/saslprep.jar /usr/share/pki/server/common/lib/
docker exec pki ln -s /usr/share/java/ongres-stringprep/stringprep.jar /usr/share/pki/server/common/lib/
docker exec pki pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up database drivers (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install ACME in PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/acme.cfg \
    -s ACME \
    -D acme_database_type=postgresql \
    -D acme_database_url="jdbc:postgresql://postgresql.example.com:5432/acme?ssl=true&sslmode=require" \
    -D acme_database_password=mysecretpassword \
    -D acme_issuer_url=https://pki.example.com:8443 \
    -D acme_realm_type=postgresql \
    -D acme_realm_url="jdbc:postgresql://postgresql.example.com:5432/acme?ssl=true&sslmode=require" \
    -D acme_realm_password=mysecretpassword \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install ACME in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME database config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/acme/database.conf
docker exec pki pki-server acme-database-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME database config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME issuer config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/acme/issuer.conf
docker exec pki pki-server acme-issuer-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME issuer config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check ACME realm config"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/acme/realm.conf
docker exec pki pki-server acme-realm-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME realm config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Run PKI healthcheck in PKI container"
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
    echo "FAIL: Run PKI healthcheck in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify ACME in PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki acme-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify ACME in PKI container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME accounts"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM accounts' \
    acme | tee output

# there should be no accounts
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME accounts (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME orders"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM orders' \
    acme | tee output

# there should be no orders
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME orders (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME authorizations"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorizations' \
    acme | tee output

# there should be no authorizations
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME authorizations (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME challenges"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorization_challenges' \
    acme | tee output

# there should be no challenges
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME challenges (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check initial ACME certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM certificates' \
    acme | tee output

# there should be no certs
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check initial ACME certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after ACME installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# there should be 7 certs
echo "7" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after ACME installation (rc=$_rc)" >&2
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

step "Install certbot in client container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client dnf install -y certbot
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install certbot in client container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Register ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot register \
    --server http://pki.example.com:8080/acme/directory \
    --email testuser@example.com \
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

step "Check ACME accounts after registration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM accounts LEFT JOIN account_contacts ON accounts.id = account_contacts.account_id' \
    acme | tee output
    
# there should be one account
echo "1" > expected
cat output | wc -l > actual
diff expected actual

# status should be valid
echo "valid" > expected
cat output |  awk -F '|' '{ print $3 }'  > actual
diff expected actual

# email should be testuser@example.com
echo "mailto:testuser@example.com" > expected
cat output |  awk -F '|' '{ print $6 }' > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after registration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enroll client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot certonly \
    --server http://pki.example.com:8080/acme/directory \
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
docker exec client pki client-cert-import \
    --cert /etc/letsencrypt/live/client.example.com/fullchain.pem \
    client1

# store serial number
docker exec client pki nss-cert-show client1 | tee output
sed -n 's/^ *Serial Number: *\(.*\)/\1/p' output > serial1.txt

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME orders after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM orders' \
    acme | tee output

# there should be one order
echo "1" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME orders after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME authorizations after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorizations' \
    acme | tee output

# there should be one authorization
echo "1" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME authorizations after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME challenges after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorization_challenges' \
    acme | tee output

# there should be one challenge
echo "1" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME challenges after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME certs after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM certificates' \
    acme | tee output

# there should be no certs (they are stored in CA)
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME certs after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# there should be 8 certs
echo "8" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check client cert
SERIAL=$(cat serial1.txt)
docker exec pki pki ca-cert-show $SERIAL | tee output

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after enrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Renew client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot renew \
    --server http://pki.example.com:8080/acme/directory \
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

step "Check renewed client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client pki client-cert-import \
    --cert /etc/letsencrypt/live/client.example.com/fullchain.pem \
    client2

# store serial number
docker exec client pki nss-cert-show client2 | tee output
sed -n 's/^ *Serial Number: *\(.*\)/\1/p' output > serial2.txt

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check renewed client cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME orders after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM orders' \
    acme | tee output

# there should be two orders
echo "2" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME orders after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME authorizations after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorizations' \
    acme | tee output

# there should be two authorizations
echo "2" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME authorizations after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME challenges after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM authorization_challenges' \
    acme | tee output

# there should be two challenges
echo "2" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME challenges after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM certificates' \
    acme | tee output

# there should be no certs (they are stored in CA)
echo "0" > expected
cat output | wc -l > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA certs after renewal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# there should be 9 certs
echo "9" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check renewed client cert
SERIAL=$(cat serial2.txt)
docker exec pki pki ca-cert-show $SERIAL | tee output

# subject should be CN=client.example.com
echo "CN=client.example.com" > expected
sed -n 's/^ *Subject DN: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after renewal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Revoke client cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot revoke \
    --server http://pki.example.com:8080/acme/directory \
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

step "Check CA certs after revocation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki ca-cert-find | tee output

# there should be 9 certs
echo "9" > expected
{ grep "Serial Number:" output || true; } | wc -l > actual
diff expected actual

# check original client cert
SERIAL=$(cat serial1.txt)
docker exec pki pki ca-cert-show $SERIAL | tee output

# status should be valid
echo "VALID" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual

# check renewed-then-revoked client cert
SERIAL=$(cat serial2.txt)
docker exec pki pki ca-cert-show $SERIAL | tee output

# status should be revoked
echo "REVOKED" > expected
sed -n 's/^ *Status: *\(.*\)/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA certs after revocation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot update_account \
    --server http://pki.example.com:8080/acme/directory \
    --email newuser@example.com \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME accounts after update"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM accounts LEFT JOIN account_contacts ON accounts.id = account_contacts.account_id' \
    acme | tee output

# there should be one account
echo "1" > expected
cat output | wc -l > actual
diff expected actual

# email should be newuser@example.com
echo "mailto:newuser@example.com" > expected
cat output |  awk -F '|' '{ print $6 }' > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after update (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME account"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec client certbot unregister \
    --server http://pki.example.com:8080/acme/directory \
    --non-interactive
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME account (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME accounts after unregistration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec  postgresql psql -U acme \
    -t -A -c 'SELECT * FROM accounts LEFT JOIN account_contacts ON accounts.id = account_contacts.account_id' \
    acme | tee output

# there should be one account
echo "1" > expected
cat output | wc -l > actual
diff expected actual

# status should be deactivated
echo "deactivated" > expected
cat output |  awk -F '|' '{ print $3 }' > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME accounts after unregistration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove ACME from PKI container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pkidestroy -s ACME -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove ACME from PKI container (rc=$_rc)" >&2
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

step "Check DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs ds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
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

step "Check ACME debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/lib/pki/pki-tomcat/logs/acme -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check certbot log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec client cat /var/log/letsencrypt/letsencrypt.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check certbot log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== acme-postgresql-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== acme-postgresql-test PASSED ===="
