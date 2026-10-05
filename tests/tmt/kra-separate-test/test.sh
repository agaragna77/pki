#!/bin/bash
# Generated TMT port of .github/workflows/kra-separate-test.yml
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
    docker rm -f kra rootca subca 2>/dev/null || true
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

step "Set up root CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=rootcads.example.com \
    --network=example \
    --network-alias=rootcads.example.com \
    --password=Secret.123 \
    rootcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up root CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=rootca.example.com \
    --network=example \
    --network-alias=rootca.example.com \
    rootca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up root CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://rootcads.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca pki-server status | tee output

# root CA should be a domain manager
echo "True" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain config in root CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# root CA should run security domain service
cat > expected << EOF
securitydomain.checkIP=false
securitydomain.checkinterval=300000
securitydomain.flushinterval=86400000
securitydomain.host=rootca.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=EXAMPLE
securitydomain.select=new
securitydomain.source=ldap
EOF

docker exec rootca pki-server ca-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check root CA certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca pki -d /var/lib/pki/pki-tomcat/conf/alias nss-cert-find

docker exec rootca pki-server cert-export \
    --cert-file ${SHARED}/root-ca_signing.crt \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA users"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca pki-server ca-user-find
docker exec rootca pki-server ca-user-show caadmin
docker exec rootca pki-server ca-user-role-find caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Set up sub CA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=subcads.example.com \
    --network=example \
    --network-alias=subcads.example.com \
    --password=Secret.123 \
    subcads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up sub CA DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up sub CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=subca.example.com \
    --network=example \
    --network-alias=subca.example.com \
    subca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up sub CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pkispawn \
    -f /usr/share/pki/server/examples/installation/subca.cfg \
    -s CA \
    -D pki_cert_chain_path=${SHARED}/root-ca_signing.crt \
    -D pki_ds_url=ldap://subcads.example.com:3389 \
    -D pki_security_domain_uri=https://rootca.example.com:8443 \
    -D pki_subordinate_create_new_security_domain=True \
    -D pki_subordinate_security_domain_name=SUBORDINATE \
    -D pki_issuing_ca_uri=https://rootca.example.com:8443 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server status | tee output

# this sub CA should be a domain manager since it's created with
# pki_subordinate_create_new_security_domain=True
echo "True" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check sub CA certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca pki -d /var/lib/pki/pki-tomcat/conf/alias nss-cert-find

docker exec subca pki-server cert-export \
    --cert-file ${SHARED}/ca_signing.crt \
    ca_signing
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA users"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca pki-server ca-user-find
docker exec subca pki-server ca-user-show caadmin
docker exec subca pki-server ca-user-role-find caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check security domain config in sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# sub CA should run security domain service
cat > expected << EOF
securitydomain.checkIP=false
securitydomain.checkinterval=300000
securitydomain.flushinterval=86400000
securitydomain.host=subca.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=SUBORDINATE
securitydomain.select=new
securitydomain.source=ldap
EOF

docker exec subca pki-server ca-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Export subordinate CA cert bundle"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
cat root-ca_signing.crt > cert_chain.crt
cat ca_signing.crt >> cert_chain.crt

cat cert_chain.crt
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Export subordinate CA cert bundle (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in sub CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in sub CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify sub CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki nss-cert-import \
    --cert ${SHARED}/root-ca_signing.crt \
    --trust CT,C,C

docker exec subca pki nss-cert-import \
    --cert ${SHARED}/ca_signing.crt \
    --trust CT,C,C

docker exec subca pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

docker exec subca pki -n caadmin --ignore-banner ca-user-show caadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify sub CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up KRA DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=krads.example.com \
    --network=example \
    --network-alias=krads.example.com \
    --password=Secret.123 \
    krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up KRA DS container (rc=$_rc)" >&2
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

step "Install KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pki-server cert-export \
    --cert-file ${SHARED}/ca_signing.crt \
    ca_signing
docker exec subca cp /root/.dogtag/pki-tomcat/ca_admin.cert ${SHARED}/ca_admin.cert
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_security_domain_uri=https://subca.example.com:8443 \
    -D pki_issuing_ca_uri=https://subca.example.com:8443 \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=${SHARED}/cert_chain.crt \
    -D pki_admin_cert_file=${SHARED}/ca_admin.cert \
    -D pki_ds_url=ldap://krads.example.com:3389 \
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

step "Check KRA server status"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server status | tee output

# KRA should not be a domain manager
echo "False" > expected
sed -n 's/^ *SD Manager: *\(.*\)$/\1/p' output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA server status (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check security domain config in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# KRA should join existing security domain in sub CA
cat > expected << EOF
securitydomain.host=subca.example.com
securitydomain.httpport=8080
securitydomain.httpsadminport=8443
securitydomain.name=SUBORDINATE
securitydomain.select=existing
EOF

docker exec kra pki-server kra-config-find | grep ^securitydomain. | sort | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check security domain config in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA certs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra pki -d /var/lib/pki/pki-tomcat/conf/alias nss-cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA users"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-find
docker exec kra pki-server kra-user-show kraadmin
docker exec kra pki-server kra-user-role-find kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Install banner in KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify KRA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki nss-cert-import \
    --cert ${SHARED}/root-ca_signing.crt \
    --trust CT,C,C

docker exec kra pki nss-cert-import \
    --cert ${SHARED}/ca_signing.crt \
    --trust CT,C,C

docker exec subca cp /root/.dogtag/pki-tomcat/ca_admin_cert.p12 ${SHARED}/ca_admin_cert.p12
docker exec kra pki pkcs12-import \
    --pkcs12 ${SHARED}/ca_admin_cert.p12 \
    --pkcs12-password Secret.123
docker exec kra pki -n caadmin --ignore-banner kra-user-show kraadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify KRA connector in sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server cert-export \
    --cert-file $SHARED/kra_transport.crt \
    kra_transport

TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec subca pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be configured
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=kra.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystem
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec subca pki -n caadmin --ignore-banner ca-kraconnector-show | tee output
sed -n 's/\s*Host:\s\+\(\S\+\):.*/\1/p' output > actual
echo kra.example.com > expected
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify KRA connector in sub CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pkidestroy \
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

step "Remove sub CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca pkidestroy -s CA -v
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
docker exec rootca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove root CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check for root CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec rootca ls -l
docker exec rootca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for root CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server systemd journal in root CA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in root CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check root CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec rootca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check root CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for sub CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec subca ls -l
docker exec subca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for sub CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server systemd journal in sub CA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in sub CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check sub CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec subca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check sub CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for KRA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra ls -l
docker exec kra find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for KRA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server systemd journal in KRA container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in KRA container (rc=$_rc)" >&2
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
    echo "==== kra-separate-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== kra-separate-test PASSED ===="
