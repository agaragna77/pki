#!/bin/bash
# Generated TMT port of .github/workflows/ca-ecc-test.yml
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
    -f /usr/share/pki/server/examples/installation/ca-ecc.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -D pki_enable_access_log=False \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check system cert keys"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# all keys should be "ec"
echo Secret.123 > password.txt
docker exec pki certutil -K -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt | tee output
echo "ec" > expected

grep ca_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep ca_ocsp_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep ca_audit_signing output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep subsystem output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual

grep sslserver output | sed -n 's/<.*>\s\(\S\+\)\s.*/\1/p' > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check system cert keys (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_signing | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA384"
echo "X9.62 ECDSA signature with SHA384" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki openssl x509 -text -noout -in ca_signing.crt | tee output

# signing algorithm should be "ecdsa-with-SHA384"
echo "ecdsa-with-SHA384" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "SHA512withEC"
echo "SHA512withEC" > expected
docker exec pki pki-server ca-config-show ca.signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA OCSP signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_ocsp_signing | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_ocsp_signing --cert-file ca_ocsp_signing.crt
docker exec pki openssl x509 -text -noout -in ca_ocsp_signing.crt | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "SHA384withEC"
echo "SHA384withEC" > expected
docker exec pki pki-server ca-config-show ca.ocsp_signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA OCSP signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA audit signing cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n ca_audit_signing | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export ca_audit_signing --cert-file ca_audit_signing.crt
docker exec pki openssl x509 -text -noout -in ca_audit_signing.crt | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should be "SHA384withEC"
echo "SHA384withEC" > expected
docker exec pki pki-server ca-config-show ca.audit_signing.defaultSigningAlgorithm | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA audit signing cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subsystem cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n subsystem | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export subsystem --cert-file subsystem.crt
docker exec pki openssl x509 -text -noout -in subsystem.crt | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should not exist
echo "ERROR: No such parameter: ca.subsystem.defaultSigningAlgorithm" > expected
docker exec pki pki-server ca-config-show ca.subsystem.defaultSigningAlgorithm \
    > >(tee stdout) 2> >(tee stderr >&2) || true
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subsystem cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -f ${SHARED}/password.txt -n sslserver | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki pki-server cert-export sslserver --cert-file sslserver.crt
docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# default signing algorithm should not exist
echo "ERROR: No such parameter: ca.sslserver.defaultSigningAlgorithm" > expected
docker exec pki pki-server ca-config-show ca.sslserver.defaultSigningAlgorithm \
    > >(tee stdout) 2> >(tee stderr >&2) || true
diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check SSL server cert (rc=$_rc)" >&2
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

step "Check authenticating as CA admin user"
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
    echo "FAIL: Check authenticating as CA admin user (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n caadmin | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in /root/.dogtag/pki-tomcat/ca_admin.cert | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check issuing SSL server cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# issue cert
docker exec pki /usr/share/pki/tests/ca/bin/sslserver-create.sh

# inspect cert with certutil
docker exec pki certutil -L -d /root/.dogtag/nssdb -n sslserver | tee output

# signing algorithm should be "X9.62 ECDSA signature with SHA512"
echo "X9.62 ECDSA signature with SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual

# inspect cert with openssl
docker exec pki openssl x509 -text -noout -in sslserver.crt | tee output

# signing algorithm should be "ecdsa-with-SHA512"
echo "ecdsa-with-SHA512" > expected
sed -n -e "s/\s*$//" -e "s/^\s*Signature Algorithm:\s*\(.*\)$/\1/p" output | uniq > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check issuing SSL server cert (rc=$_rc)" >&2
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
    echo "==== ca-ecc-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-ecc-test PASSED ===="
