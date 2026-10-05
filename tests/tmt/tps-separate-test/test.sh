#!/bin/bash
# Generated TMT port of .github/workflows/tps-separate-test.yml
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
    docker rm -f ca cads kra krads tks tksds tps tpsds 2>/dev/null || true
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
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up CA DS container (rc=$_rc)" >&2
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

step "Install CA in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://cads.example.com:3389 \
    -v

docker exec ca pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in CA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in CA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in CA container (rc=$_rc)" >&2
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

step "Install KRA in KRA container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server cert-export ca_signing --cert-file ${SHARED}/ca_signing.crt
docker exec ca cp /root/.dogtag/pki-tomcat/ca_admin.cert ${SHARED}/ca_admin.cert
docker exec kra pkispawn \
    -f /usr/share/pki/server/examples/installation/kra.cfg \
    -s KRA \
    -D pki_security_domain_hostname=ca.example.com \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_admin_cert_file=${SHARED}/ca_admin.cert \
    -D pki_ds_url=ldap://krads.example.com:3389 \
    -D pki_http_enable=False \
    -v

docker exec kra pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in KRA container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify there is no plain HTTP connectors in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server http-connector-find | tee output

echo "Secure" > expected
sed -n -e "s/^ *Connector ID: *\(.*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify there is no plain HTTP connectors in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
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

step "Set up TKS DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tksds.example.com \
    --network=example \
    --network-alias=tksds.example.com \
    --password=Secret.123 \
    tksds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=tks.example.com \
    --network=example \
    --network-alias=tks.example.com \
    tks
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TKS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TKS in TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pkispawn \
    -f /usr/share/pki/server/examples/installation/tks.cfg \
    -s TKS \
    -D pki_security_domain_hostname=ca.example.com \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_admin_cert_file=${SHARED}/ca_admin.cert \
    -D pki_ds_url=ldap://tksds.example.com:3389 \
    -D pki_http_enable=False \
    -v

docker exec tks pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TKS in TKS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify there is no plain HTTP connectors in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server http-connector-find | tee output

echo "Secure" > expected
sed -n -e "s/^ *Connector ID: *\(.*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify there is no plain HTTP connectors in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in TKS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in TKS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS DS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/ds-create.sh \
    --image=${DS_IMAGE} \
    --hostname=tpsds.example.com \
    --network=example \
    --network-alias=tpsds.example.com \
    --password=Secret.123 \
    tpsds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS DS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Set up TPS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --hostname=tps.example.com \
    --network=example \
    --network-alias=tps.example.com \
    tps
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up TPS container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install TPS in TPS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pkispawn \
    -f /usr/share/pki/server/examples/installation/tps.cfg \
    -s TPS \
    -D pki_security_domain_hostname=ca.example.com \
    -D pki_cert_chain_nickname=ca_signing \
    -D pki_cert_chain_path=${SHARED}/ca_signing.crt \
    -D pki_admin_cert_file=${SHARED}/ca_admin.cert \
    -D pki_ca_uri=https://ca.example.com:8443 \
    -D pki_kra_uri=https://kra.example.com:8443 \
    -D pki_tks_uri=https://tks.example.com:8443 \
    -D pki_ds_url=ldap://tpsds.example.com:3389 \
    -D pki_authdb_url=ldap://tpsds.example.com:3389 \
    -D pki_enable_server_side_keygen=True \
    -D pki_http_enable=False \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install TPS in TPS container (rc=$_rc)" >&2
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

step "Check TPS certs"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server cert-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS certs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify there is no plain HTTP connectors in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server http-connector-find | tee output

echo "Secure" > expected
sed -n -e "s/^ *Connector ID: *\(.*\)$/\1/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify there is no plain HTTP connectors in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify there is no plain HTTP ports in security domain but CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-sd-subsystem-find | tee output

echo "  Port: 8080" > expected
sed -ne "/^ *Port:/p" output > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify there is no plain HTTP ports in security domain but CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install banner in TPS container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps cp /usr/share/pki/server/examples/banner/banner.txt /var/lib/pki/pki-tomcat/conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install banner in TPS container (rc=$_rc)" >&2
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
    docker exec tps pki-healthcheck --failures-only
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

step "Check TPS admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca cp /root/.dogtag/pki-tomcat/ca_admin_cert.p12 ${SHARED}/ca_admin_cert.p12

docker exec tps pki nss-cert-import \
    --cert $SHARED/ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec tps pki pkcs12-import \
    --pkcs12 ${SHARED}/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

docker exec tps pki -n caadmin --ignore-banner \
    tps-user-show tpsadmin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pki-server ca-user-show TPS-tps.example.com-8443
docker exec ca pki-server ca-user-role-find TPS-tps.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in KRA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec kra pki-server kra-user-show TPS-tps.example.com-8443
docker exec kra pki-server kra-user-role-find TPS-tps.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in KRA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS subsystem user in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-user-show TPS-tps.example.com-8443
docker exec tks pki-server tks-user-role-find TPS-tps.example.com-8443
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS subsystem user in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS users"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-user-find
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS users (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check connectors in TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pki-server tps-connector-find | tee output

cat > expected << EOF
  Connector ID: ca1
  Type: CA
  Enabled: true
  URL: https://ca.example.com:8443
  Nickname: subsystem

  Connector ID: kra1
  Type: KRA
  Enabled: true
  URL: https://kra.example.com:8443
  Nickname: subsystem

  Connector ID: tks1
  Type: TKS
  Enabled: true
  URL: https://tks.example.com:8443
  Nickname: subsystem
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check connectors in TPS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS connector in TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pki-server tks-connector-find | tee output

cat > expected << EOF
  Connector ID: 0
  URL: https://tps.example.com:8443
  Nickname: TPS-tps.example.com-8443 sharedSecret
  User ID: TPS-tps.example.com-8443
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS connector in TKS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove TPS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps pkidestroy \
    -s TPS \
    --debug \
    > >(tee stdout) 2> >(tee stderr >&2)
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TPS (rc=$_rc)" >&2
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

step "Remove TKS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks pkidestroy -s TKS -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove TKS (rc=$_rc)" >&2
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

step "Remove CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca pkidestroy -s CA -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec cads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs cads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for CA core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec ca ls -l
docker exec ca find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for CA core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec ca find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec krads journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs krads
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA DS container logs (rc=$_rc)" >&2
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

step "Check KRA systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec kra find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA access log (rc=$_rc)" >&2
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

step "Check TKS DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tksds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tksds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for TKS core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec tks ls -l
docker exec tks find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for TKS core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TKS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tks find /var/lib/pki/pki-tomcat/logs/tks -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS DS server systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tpsds journalctl -x --no-pager -u dirsrv@localhost.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS DS server systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS DS container logs"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker logs tpsds
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS DS container logs (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check for TPS core dumps"
# GHA if: failure() — run only if a prior step failed
if [[ "$GHA_FAILED" -ne 0 ]]; then
set +e
(
set -euo pipefail
docker exec tps ls -l
docker exec tps find / -path /proc -prune -o -name "hs_err_pid*.log" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check for TPS core dumps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS systemd journal"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tps journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS systemd journal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tps find /var/lib/pki/pki-tomcat/logs -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS access log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check TPS debug log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec tps find /var/lib/pki/pki-tomcat/logs/tps -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS debug log (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== tps-separate-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== tps-separate-test PASSED ===="
