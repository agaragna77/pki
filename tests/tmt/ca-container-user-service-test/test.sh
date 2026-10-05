#!/bin/bash
# Generated TMT port of .github/workflows/ca-container-user-service-test.yml
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

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: jq
# Most are available in the pki-runner container or Fedora host.
command -v jq >/dev/null 2>&1 || dnf install -y jq 2>/dev/null || true
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
    --hostname=ca.example.com \
    --network=example \
    pki
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

step "Install Podman"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki dnf install -y podman sqlite fuse-overlayfs
docker exec pki ls -lR /usr/share/containers
docker exec pki cat /usr/share/containers/containers.conf
docker exec pki cat /usr/share/containers/storage.conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install Podman (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure Podman"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# enable SETUID and SETGID capabilities
# https://github.com/containers/podman/discussions/21739
docker exec pki setcap cap_setuid+ep /usr/bin/newuidmap
docker exec pki setcap cap_setgid+ep /usr/bin/newgidmap

# enable login shell
docker exec pki usermod -s /bin/bash pkiuser

# enable access to systemd journal
docker exec pki usermod -a -G systemd-journal pkiuser

# add subordinate UID and GID ranges
# https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md
docker exec pki usermod --add-subuids 100000-165535 --add-subgids 100000-165535 pkiuser

# enable systemd linger
# https://blog.christophersmart.com/2021/02/20/rootless-podman-containers-under-system-accounts-managed-and-enabled-at-boot-with-systemd/
docker exec pki loginctl enable-linger pkiuser

# use fuse-overlayfs
# https://github.com/containers/podman/issues/8705#issuecomment-744357805
docker exec pki ls -lR /home
docker exec -u pkiuser pki mkdir -p /home/pkiuser/.config/containers
docker exec -i -u pkiuser pki tee /home/pkiuser/.config/containers/storage.conf << EOF
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF

docker exec -u pkiuser pki podman info --format=json | tee output

# rootless should be enabled
echo "true" > expected
jq -r '.host.security.rootless' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure Podman (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load PKI images into PKI user's space"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp pki-images.tar pki:/home/pkiuser
docker exec pki chown pkiuser /home/pkiuser/pki-images.tar

docker exec -u pkiuser pki podman load --input /home/pkiuser/pki-images.tar
docker exec -u pkiuser pki podman images
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Load PKI images into PKI user's space (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create shared folders in PKI user's home directory"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create folders with default owner and permissions
docker exec -u pkiuser pki mkdir -p /home/pkiuser/.dogtag/pki-ca/conf
docker exec -u pkiuser pki mkdir -p /home/pkiuser/.dogtag/pki-ca/logs

docker exec pki ls -laR /home/pkiuser
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create shared folders in PKI user's home directory (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA user service"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# create container unit file
# https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html
docker exec -u pkiuser pki mkdir -p /home/pkiuser/.config/containers/systemd
docker exec -i -u pkiuser pki tee /home/pkiuser/.config/containers/systemd/pki-ca.container << EOF
[Unit]
Description=PKI CA

[Container]
Image=pki-ca
Network=host

# run container as PKI user
User=pkiuser
Group=pkiuser
UserNS=keep-id

# use shared folders in home directory
Volume=/home/pkiuser/.dogtag/pki-ca/conf:/conf
Volume=/home/pkiuser/.dogtag/pki-ca/logs:/logs

# configure DS connection
Environment=PKI_DS_URL=ldap://ds.example.com:3389
Environment=PKI_DS_PASSWORD=Secret.123

[Install]
WantedBy=multi-user.target
EOF

# check service unit file generated by Quadlet
docker exec -u pkiuser pki /usr/libexec/podman/quadlet -dryrun -user

# reload service unit files using login shell
docker exec pki sudo -i -u pkiuser systemctl --user daemon-reload
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA user service (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run CA user service"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# start service using login shell
docker exec pki sudo -i -u pkiuser systemctl --user start pki-ca.service
docker exec -u pkiuser pki podman ps

# wait for CA to start
docker exec -u pkiuser pki curl \
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
    echo "FAIL: Run CA user service (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Get Tomcat flavor"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TOMCAT_FLAVOR=$(docker exec pki test -f /usr/libexec/tomcat/tomcat-run.sh && echo "new" || echo "old")
echo "TOMCAT_FLAVOR=$TOMCAT_FLAVOR" | tee -a $GITHUB_ENV
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Get Tomcat flavor (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
source_gha_env
fi

step "Check conf dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki ls -l /home/pkiuser/.dogtag/pki-ca/conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by pkiuser group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- pkiuser Catalina
drwxrwx--- pkiuser alias
drwxrwx--- pkiuser ca
-rw-rw---- pkiuser catalina.policy
lrwxrwxrwx pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser certs
lrwxrwxrwx pkiuser context.xml -> /etc/tomcat/context.xml
-rw-rw---- pkiuser jss.conf
lrwxrwxrwx pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser password.conf
-rw-rw---- pkiuser server.xml
-rw-rw---- pkiuser serverCertNick.conf
-rw-rw---- pkiuser tomcat.conf
lrwxrwxrwx pkiuser web.xml -> /etc/tomcat/web.xml
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser Catalina
drwxrwx--- pkiuser alias
drwxrwx--- pkiuser ca
-rw-rw---- pkiuser catalina.policy
lrwxrwxrwx pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxrwx--- pkiuser certs
lrwxrwxrwx pkiuser context.xml -> /etc/tomcat/context.xml
-rw-rw---- pkiuser jss.conf
lrwxrwxrwx pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser password.conf
-rw-rw---- pkiuser server.xml
-rw-rw---- pkiuser serverCertNick.conf
-rw-rw---- pkiuser tomcat.conf
lrwxrwxrwx pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conf dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check conf/alias dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki ls -l /home/pkiuser/.dogtag/pki-ca/conf/alias \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

# everything should be owned by pkiuser group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw-rw- pkiuser ca.crt
-rw------- pkiuser cert9.db
-rw------- pkiuser key4.db
-rw------- pkiuser pkcs11.txt
EOF

cat > expected_new << EOF
-rw-rw-rw- pkiuser ca.crt
-rw------- pkiuser cert9.db
-rw------- pkiuser key4.db
-rw------- pkiuser pkcs11.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conf/alias dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check conf/ca dir"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki ls -l /home/pkiuser/.dogtag/pki-ca/conf/ca \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
        -e '/^\S* *\S* *\S* *CS.cfg.bak /d' \
    | tee output

# everything should be owned by pkiuser group
# TODO: review owners/permissions
cat > expected_old << EOF
-rw-rw---- pkiuser CS.cfg
-rw-rw---- pkiuser adminCert.profile
drwxrwxrwx pkiuser archives
-rw-rw---- pkiuser caAuditSigningCert.profile
-rw-rw---- pkiuser caCert.profile
-rw-rw---- pkiuser caOCSPCert.profile
drwxrwx--- pkiuser emails
-rw-rw---- pkiuser flatfile.txt
drwxrwx--- pkiuser profiles
-rw-rw---- pkiuser proxy.conf
-rw-rw---- pkiuser registry.cfg
-rw-rw---- pkiuser serverCert.profile
-rw-rw---- pkiuser subsystemCert.profile
EOF

cat > expected_new << EOF
-rw-rw---- pkiuser CS.cfg
-rw-rw---- pkiuser adminCert.profile
drwxrwxrwx pkiuser archives
-rw-rw---- pkiuser caAuditSigningCert.profile
-rw-rw---- pkiuser caCert.profile
-rw-rw---- pkiuser caOCSPCert.profile
drwxrwx--- pkiuser emails
-rw-rw---- pkiuser flatfile.txt
drwxrwx--- pkiuser profiles
-rw-rw---- pkiuser proxy.conf
-rw-rw---- pkiuser registry.cfg
-rw-rw---- pkiuser serverCert.profile
-rw-rw---- pkiuser subsystemCert.profile
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check conf/ca dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
docker exec -u pkiuser pki ls -l /home/pkiuser/.dogtag/pki-ca/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by pkiuser group
# TODO: review owners/permissions
cat > expected << EOF
drwxrwx--- pkiuser backup
drwxrwx--- pkiuser ca
-rw-rw---- pkiuser localhost.$DATE.log
-rw-rw-rw- pkiuser localhost_access_log.$DATE.txt
drwxrwx--- pkiuser pki
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check logs dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
docker exec -u pkiuser pki ls -l /home/pkiuser/.dogtag/pki-ca/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\S* *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# everything should be owned by pkiuser group
# TODO: review owners/permissions
cat > expected_old << EOF
drwxrwx--- pkiuser backup
drwxrwx--- pkiuser ca
-rw-rw-rw- pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxrwx--- pkiuser backup
drwxrwx--- pkiuser ca
-rw-rw-rw- pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check logs dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server cert-export \
    --cert-file /conf/certs/ca_signing.crt \
    ca_signing

docker exec -u pkiuser pki pki nss-cert-import \
    --cert /home/pkiuser/.dogtag/pki-ca/conf/certs/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec -u pkiuser pki pki info
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
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-db-init -v
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-db-index-add -v
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-db-index-rebuild -v
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
docker exec -u pkiuser pki pki nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr /home/pkiuser/admin.csr

docker exec -u pkiuser pki podman cp /home/pkiuser/admin.csr systemd-pki-ca:/home/pkiuser

# issue cert
docker exec -u pkiuser pki podman exec systemd-pki-ca pki-server ca-cert-create \
    --csr /home/pkiuser/admin.csr \
    --profile /usr/share/pki/ca/conf/rsaAdminCert.profile \
    --cert /home/pkiuser/admin.crt \
    --import-cert

docker exec -u pkiuser pki podman cp systemd-pki-ca:/home/pkiuser/admin.crt /home/pkiuser

# import cert
docker exec -u pkiuser pki pki nss-cert-import \
    --cert /home/pkiuser/admin.crt \
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
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --cert /home/pkiuser/admin.crt \
    admin

# add CA admin user into CA groups
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-user-role-add admin "Administrators"
docker exec -u pkiuser pki podman exec systemd-pki-ca \
    pki-server ca-user-role-add admin "Certificate Manager Agents"
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
docker exec -u pkiuser pki pki \
    -n admin \
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

step "Check cert enrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -u pkiuser pki pki \
    client-cert-request \
    uid=testuser | tee output

REQUEST_ID=$(sed -n -e 's/^ *Request ID: *\(.*\)$/\1/p' output)
echo "REQUEST_ID: $REQUEST_ID"

docker exec -u pkiuser pki pki \
    -n admin \
    ca-cert-request-approve \
    $REQUEST_ID \
    --force
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check cert enrollment (rc=$_rc)" >&2
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

step "Check CA container systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki journalctl --user -x --no-pager -u pki-ca.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki podman logs systemd-pki-ca 2>&1
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec -u pkiuser pki find /home/pkiuser/.dogtag/pki-ca/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-container-user-service-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-container-user-service-test PASSED ===="
