#!/bin/bash
# Generated TMT port of .github/workflows/ca-existing-ds-test.yml
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

step "Create PKI server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create
docker exec pki pki-server nss-create --no-password
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create PKI server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA signing cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=CA Signing Certificate" \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    ca_signing
docker exec pki pki-server cert-create \
    --ext /usr/share/pki/server/certs/ca_signing.conf \
    ca_signing
docker exec pki pki-server cert-import \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA signing cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA OCSP signing cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=OCSP Signing Certificate" \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    ca_ocsp_signing
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/ocsp_signing.conf \
    ca_ocsp_signing
docker exec pki pki-server cert-import \
    ca_ocsp_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA OCSP signing cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA audit signing cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=Audit Signing Certificate" \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    ca_audit_signing
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/audit_signing.conf \
    ca_audit_signing
docker exec pki pki-server cert-import \
    ca_audit_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA audit signing cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create subsystem cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=Subsystem Certificate" \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    subsystem
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/subsystem.conf \
    subsystem
docker exec pki pki-server cert-import \
    subsystem
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create subsystem cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create SSL server cert in server's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-request \
    --subject "CN=pki.example.com" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    sslserver
docker exec pki pki-server cert-create \
    --issuer ca_signing \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    sslserver
docker exec pki pki-server cert-import \
    sslserver
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create SSL server cert in server's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA admin cert in client's NSS database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    nss-cert-request \
    --subject "CN=Administrator" \
    --ext /usr/share/pki/server/certs/admin.conf \
    --csr admin.csr
docker exec pki pki \
    -d /var/lib/pki/pki-tomcat/conf/alias \
    nss-cert-issue \
    --issuer ca_signing \
    --csr admin.csr \
    --ext /usr/share/pki/server/certs/admin.conf \
    --cert admin.crt

docker exec pki pki nss-cert-import \
    --cert admin.crt \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA admin cert in client's NSS database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca
docker exec pki pki-server ca --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server ca-create CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-create --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server ca-create CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create CA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create CA subsystem (rc=$_rc)" >&2
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

step "Configure connection to CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# store DS password
docker exec pki pki-server password-set \
    --password Secret.123 \
    internaldb

# configure DS connection params
docker exec pki pki-server ca-db-config-mod \
    --hostname ds.example.com \
    --port 3389 \
    --secure false \
    --auth BasicAuth \
    --bindDN "cn=Directory Manager" \
    --bindPWPrompt internaldb \
    --database userroot \
    --baseDN dc=ca,dc=pki,dc=example,dc=com \
    --multiSuffix false \
    --maxConns 15 \
    --minConns 3

# configure CA user/group subsystem
docker exec pki pki-server ca-config-set usrgrp.ldap internaldb

# configure CA database subsystem
docker exec pki pki-server ca-config-set dbs.ldap internaldb
docker exec pki pki-server ca-config-set dbs.newSchemaEntryAdded true
docker exec pki pki-server ca-config-set dbs.requestDN ou=ca,ou=requests
docker exec pki pki-server ca-config-set dbs.request.id.generator random
docker exec pki pki-server ca-config-set dbs.serialDN ou=certificateRepository,ou=ca
docker exec pki pki-server ca-config-set dbs.cert.id.generator random
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure connection to CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check connection to CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-db-info
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check connection to CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Initialize CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-db-init -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Initialize CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-db-index-add -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Rebuild CA search indexes"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-db-index-rebuild -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Rebuild CA search indexes (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/ca_signing.crt \
    --csr /var/lib/pki/pki-tomcat/conf/certs/ca_signing.csr \
    --profile /usr/share/pki/ca/conf/caCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA OCSP signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/ca_ocsp_signing.crt \
    --csr /var/lib/pki/pki-tomcat/conf/certs/ca_ocsp_signing.csr \
    --profile /usr/share/pki/ca/conf/caOCSPCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA OCSP signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import CA audit signing cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/ca_audit_signing.crt \
    --csr /var/lib/pki/pki-tomcat/conf/certs/ca_audit_signing.csr \
    --profile /usr/share/pki/ca/conf/caAuditSigningCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import CA audit signing cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import subsystem cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/subsystem.crt \
    --csr /var/lib/pki/pki-tomcat/conf/certs/subsystem.csr \
    --profile /usr/share/pki/ca/conf/rsaSubsystemCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import subsystem cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import SSL server cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert /var/lib/pki/pki-tomcat/conf/certs/sslserver.crt \
    --csr /var/lib/pki/pki-tomcat/conf/certs/sslserver.csr \
    --profile /usr/share/pki/ca/conf/rsaServerCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import SSL server cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Import admin cert into CA database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-cert-import \
    --cert admin.crt \
    --csr admin.csr \
    --profile /usr/share/pki/ca/conf/rsaAdminCert.profile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Import admin cert into CA database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create security domain database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-sd-create \
    --name EXAMPLE
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create security domain database (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure security domain manager"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# configure CA as security domain manager
docker exec pki pki-server ca-config-set securitydomain.select new
docker exec pki pki-server ca-config-set securitydomain.name EXAMPLE
docker exec pki pki-server ca-config-set securitydomain.host pki.example.com
docker exec pki pki-server ca-config-set securitydomain.httpport 8080
docker exec pki pki-server ca-config-set securitydomain.httpsadminport 8443
docker exec pki pki-server ca-config-set securitydomain.checkIP false
docker exec pki pki-server ca-config-set securitydomain.checkinterval 300000
docker exec pki pki-server ca-config-set securitydomain.flushinterval 86400000
docker exec pki pki-server ca-config-set securitydomain.source ldap

# register CA as security domain manager
docker exec pki pki-server ca-sd-subsystem-add \
    --subsystem CA \
    --hostname pki.example.com \
    --unsecure-port 8080 \
    --secure-port 8443 \
    --domain-manager \
    "CA pki.example.com 8443"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure security domain manager (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-add \
    --full-name CA-pki.example.com-8443 \
    --type agentType \
    --cert /var/lib/pki/pki-tomcat/conf/certs/subsystem.crt \
    CA-pki.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to subsystem user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-add CA-pki.example.com-8443 "Subsystem Group"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to subsystem user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-add \
    --full-name Administrator \
    --type adminType \
    --cert admin.crt \
    caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Assign roles to CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-user-role-add caadmin "Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Certificate Manager Agents"
docker exec pki pki-server ca-user-role-add caadmin "Security Domain Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise CA Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise KRA Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise RA Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise TKS Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise OCSP Administrators"
docker exec pki pki-server ca-user-role-add caadmin "Enterprise TPS Administrators"
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Assign roles to CA admin user (rc=$_rc)" >&2
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
    -D pki_ds_setup=False \
    -D pki_share_db=True \
    -D pki_security_domain_setup=False \
    -D pki_admin_setup=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
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

step "Check CA admin user"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki -n caadmin ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA security domain"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# security domain should be enabled (i.e. securitydomain.select=new)
cat > expected << EOF
securitydomain.checkIP=false
securitydomain.checkinterval=300000
securitydomain.flushinterval=86400000
securitydomain.host=pki.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=EXAMPLE
securitydomain.select=new
securitydomain.source=ldap
EOF

docker exec pki pki-server ca-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual

# REST API should return security domain info
cat > expected << EOF
  Domain: EXAMPLE

  CA Subsystem:

    Host ID: CA pki.example.com 8443
    Hostname: pki.example.com
    Port: 8080
    Secure Port: 8443
    Domain Manager: TRUE

EOF

docker exec pki pki securitydomain-show | tee output
diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA security domain (rc=$_rc)" >&2
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

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ca-existing-ds-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-existing-ds-test PASSED ===="
