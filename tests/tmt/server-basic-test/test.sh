#!/bin/bash
# Generated TMT port of .github/workflows/server-basic-test.yml
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
    docker rm -f pki 2>/dev/null || true
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

step "Set up server container"
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
    echo "FAIL: Set up server container (rc=$_rc)" >&2
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

step "Check Tomcat lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/java/tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check Tomcat lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI lib dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -le 44 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# the following libraries should be bundled:
# - commons-cli
# - commons-codec
# - commons-io
# - commons-lang3
# - commons-logging
# - commons-net
# - httpclient
# - httpcore
# - jackson-annotations
# - jackson-core
# - jackson-databind
# - jackson-jaxrs-base
# - jackson-jaxrs-json-provider
# - jackson-module-jaxb-annotations
# - jakarta.activation-api
# - jakarta.annotation-api
# - jakarta.xml.bind-api
# - jboss-jaxrs-api_2.0_spec
# - jboss-logging
# - resteasy-client
# - resteasy-jackson2-provider
# - resteasy-jaxrs
# - slf4j-api
# - slf4j-jdk14
cat > expected << EOF
-rw-r--r-- root root commons-cli-x.y.z.jar
lrwxrwxrwx root root commons-cli.jar -> commons-cli-x.y.z.jar
-rw-r--r-- root root commons-codec-x.y.z.jar
lrwxrwxrwx root root commons-codec.jar -> commons-codec-x.y.z.jar
-rw-r--r-- root root commons-io-x.y.z.jar
lrwxrwxrwx root root commons-io.jar -> commons-io-x.y.z.jar
-rw-r--r-- root root commons-lang3-x.y.z.jar
lrwxrwxrwx root root commons-lang3.jar -> commons-lang3-x.y.z.jar
-rw-r--r-- root root commons-logging-x.y.z.jar
lrwxrwxrwx root root commons-logging.jar -> commons-logging-x.y.z.jar
-rw-r--r-- root root commons-net-x.y.z.jar
lrwxrwxrwx root root commons-net.jar -> commons-net-x.y.z.jar
-rw-r--r-- root root httpclient-x.y.z.jar
lrwxrwxrwx root root httpclient.jar -> httpclient-x.y.z.jar
-rw-r--r-- root root httpcore-x.y.z.jar
lrwxrwxrwx root root httpcore.jar -> httpcore-x.y.z.jar
-rw-r--r-- root root jackson-annotations-x.y.z.jar
lrwxrwxrwx root root jackson-annotations.jar -> jackson-annotations-x.y.z.jar
-rw-r--r-- root root jackson-core-x.y.z.jar
lrwxrwxrwx root root jackson-core.jar -> jackson-core-x.y.z.jar
-rw-r--r-- root root jackson-databind-x.y.z.jar
lrwxrwxrwx root root jackson-databind.jar -> jackson-databind-x.y.z.jar
-rw-r--r-- root root jackson-jaxrs-base-x.y.z.jar
lrwxrwxrwx root root jackson-jaxrs-base.jar -> jackson-jaxrs-base-x.y.z.jar
-rw-r--r-- root root jackson-jaxrs-json-provider-x.y.z.jar
lrwxrwxrwx root root jackson-jaxrs-json-provider.jar -> jackson-jaxrs-json-provider-x.y.z.jar
-rw-r--r-- root root jackson-module-jaxb-annotations-x.y.z.jar
lrwxrwxrwx root root jackson-module-jaxb-annotations.jar -> jackson-module-jaxb-annotations-x.y.z.jar
-rw-r--r-- root root jakarta.activation-api-x.y.z.jar
lrwxrwxrwx root root jakarta.activation-api.jar -> jakarta.activation-api-x.y.z.jar
-rw-r--r-- root root jakarta.annotation-api-x.y.z.jar
lrwxrwxrwx root root jakarta.annotation-api.jar -> jakarta.annotation-api-x.y.z.jar
-rw-r--r-- root root jakarta.xml.bind-api-x.y.z.jar
lrwxrwxrwx root root jakarta.xml.bind-api.jar -> jakarta.xml.bind-api-x.y.z.jar
-rw-r--r-- root root jboss-jaxrs-api_2.0_spec-x.y.z.Final.jar
lrwxrwxrwx root root jboss-jaxrs-api_2.0_spec.jar -> jboss-jaxrs-api_2.0_spec-x.y.z.Final.jar
-rw-r--r-- root root jboss-logging-x.y.z.Final.jar
lrwxrwxrwx root root jboss-logging.jar -> jboss-logging-x.y.z.Final.jar
lrwxrwxrwx root root jss.jar -> ../../../../usr/lib/java/jss.jar
lrwxrwxrwx root root ldapjdk.jar -> ../../../../usr/share/java/ldapjdk.jar
lrwxrwxrwx root root p11-kit-trust.so -> ../../../../usr/lib64/pkcs11/p11-kit-trust.so
lrwxrwxrwx root root pki-common.jar -> ../../../../usr/share/java/pki/pki-common.jar
lrwxrwxrwx root root pki-tools.jar -> ../../../../usr/share/java/pki/pki-tools.jar
-rw-r--r-- root root resteasy-client-x.y.z.Final.jar
-rw-r--r-- root root resteasy-jackson2-provider-x.y.z.Final.jar
lrwxrwxrwx root root resteasy-jackson2-provider.jar -> resteasy-jackson2-provider-x.y.z.Final.jar
-rw-r--r-- root root resteasy-jaxrs-x.y.z.Final.jar
lrwxrwxrwx root root resteasy-jaxrs.jar -> resteasy-jaxrs-x.y.z.Final.jar
lrwxrwxrwx root root servlet.jar -> ../../../../usr/share/java/tomcat-servlet-api.jar
-rw-r--r-- root root slf4j-api-x.y.z.jar
lrwxrwxrwx root root slf4j-api.jar -> slf4j-api-x.y.z.jar
-rw-r--r-- root root slf4j-jdk14-x.y.z.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> slf4j-jdk14-x.y.z.jar
EOF

# normalize actual result:
# - replace version number with x.y.z
# - replace servlet.jar with tomcat-servlet-api.jar
sed -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.jar$/-x.y.z.jar/' \
    -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.Final\.jar$/-x.y.z.Final.jar/' \
    -e 's/\/servlet.jar$/\/tomcat-servlet-api.jar/' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI lib dir"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 45 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# the following libraries should be bundled:
# - commons-cli
# - commons-codec
# - commons-io
# - commons-lang3
# - commons-logging
# - commons-net
# - httpclient
# - httpcore
# - jackson-annotations
# - jackson-core
# - jackson-databind
# - jackson-jaxrs-base
# - jackson-jaxrs-json-provider
# - jackson-module-jaxb-annotations
# - jakarta.activation-api
# - jakarta.annotation-api
# - jakarta.xml.bind-api
# - jboss-jaxrs-api_2.0_spec
# - jboss-logging
# - resteasy-client
# - resteasy-jackson2-provider
# - resteasy-jaxrs
# - slf4j-api
# - slf4j-jdk14
cat > expected << EOF
-rw-r--r-- root root commons-cli-x.y.z.jar
lrwxrwxrwx root root commons-cli.jar -> commons-cli-x.y.z.jar
-rw-r--r-- root root commons-codec-x.y.z.jar
lrwxrwxrwx root root commons-codec.jar -> commons-codec-x.y.z.jar
-rw-r--r-- root root commons-io-x.y.z.jar
lrwxrwxrwx root root commons-io.jar -> commons-io-x.y.z.jar
-rw-r--r-- root root commons-lang3-x.y.z.jar
lrwxrwxrwx root root commons-lang3.jar -> commons-lang3-x.y.z.jar
-rw-r--r-- root root commons-logging-x.y.z.jar
lrwxrwxrwx root root commons-logging.jar -> commons-logging-x.y.z.jar
-rw-r--r-- root root commons-net-x.y.z.jar
lrwxrwxrwx root root commons-net.jar -> commons-net-x.y.z.jar
-rw-r--r-- root root httpclient-x.y.z.jar
lrwxrwxrwx root root httpclient.jar -> httpclient-x.y.z.jar
-rw-r--r-- root root httpcore-x.y.z.jar
lrwxrwxrwx root root httpcore.jar -> httpcore-x.y.z.jar
-rw-r--r-- root root jackson-annotations-x.y.jar
lrwxrwxrwx root root jackson-annotations.jar -> jackson-annotations-x.y.jar
-rw-r--r-- root root jackson-core-x.y.z.jar
lrwxrwxrwx root root jackson-core.jar -> jackson-core-x.y.z.jar
-rw-r--r-- root root jackson-databind-x.y.z.jar
lrwxrwxrwx root root jackson-databind.jar -> jackson-databind-x.y.z.jar
-rw-r--r-- root root jackson-jaxrs-base-x.y.z.jar
lrwxrwxrwx root root jackson-jaxrs-base.jar -> jackson-jaxrs-base-x.y.z.jar
-rw-r--r-- root root jackson-jaxrs-json-provider-x.y.z.jar
lrwxrwxrwx root root jackson-jaxrs-json-provider.jar -> jackson-jaxrs-json-provider-x.y.z.jar
-rw-r--r-- root root jackson-module-jaxb-annotations-x.y.z.jar
lrwxrwxrwx root root jackson-module-jaxb-annotations.jar -> jackson-module-jaxb-annotations-x.y.z.jar
-rw-r--r-- root root jakarta.activation-api-x.y.z.jar
lrwxrwxrwx root root jakarta.activation-api.jar -> jakarta.activation-api-x.y.z.jar
-rw-r--r-- root root jakarta.annotation-api-x.y.z.jar
lrwxrwxrwx root root jakarta.annotation-api.jar -> jakarta.annotation-api-x.y.z.jar
-rw-r--r-- root root jakarta.xml.bind-api-x.y.z.jar
lrwxrwxrwx root root jakarta.xml.bind-api.jar -> jakarta.xml.bind-api-x.y.z.jar
-rw-r--r-- root root jboss-jaxrs-api_2.0_spec-x.y.z.Final.jar
lrwxrwxrwx root root jboss-jaxrs-api_2.0_spec.jar -> jboss-jaxrs-api_2.0_spec-x.y.z.Final.jar
-rw-r--r-- root root jboss-logging-x.y.z.Final.jar
lrwxrwxrwx root root jboss-logging.jar -> jboss-logging-x.y.z.Final.jar
lrwxrwxrwx root root jss.jar -> ../../../../usr/lib/java/jss.jar
lrwxrwxrwx root root ldapjdk.jar -> ../../../../usr/share/java/ldapjdk.jar
lrwxrwxrwx root root p11-kit-trust.so -> ../../../../usr/lib64/pkcs11/p11-kit-trust.so
lrwxrwxrwx root root pki-common.jar -> ../../../../usr/share/java/pki/pki-common.jar
lrwxrwxrwx root root pki-tools.jar -> ../../../../usr/share/java/pki/pki-tools.jar
-rw-r--r-- root root resteasy-client-x.y.z.Final.jar
-rw-r--r-- root root resteasy-jackson2-provider-x.y.z.Final.jar
lrwxrwxrwx root root resteasy-jackson2-provider.jar -> resteasy-jackson2-provider-x.y.z.Final.jar
-rw-r--r-- root root resteasy-jaxrs-x.y.z.Final.jar
lrwxrwxrwx root root resteasy-jaxrs.jar -> resteasy-jaxrs-x.y.z.Final.jar
lrwxrwxrwx root root servlet.jar -> ../../../../usr/share/java/tomcat-servlet-api.jar
-rw-r--r-- root root slf4j-api-x.y.z.jar
lrwxrwxrwx root root slf4j-api.jar -> slf4j-api-x.y.z.jar
-rw-r--r-- root root slf4j-jdk14-x.y.z.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> slf4j-jdk14-x.y.z.jar
EOF

# normalize actual result:
# - replace version number with x.y or x.y.z
# - replace servlet.jar with tomcat-servlet-api.jar
sed -e 's/-[0-9]*\.[0-9]*\.jar$/-x.y.jar/' \
    -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.jar$/-x.y.z.jar/' \
    -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.Final\.jar$/-x.y.z.Final.jar/' \
    -e 's/\/servlet.jar$/\/tomcat-servlet-api.jar/' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server common lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/common/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# the following libraries should be bundled:
# - resteasy-servlet-initializer
cat > expected << EOF
lrwxrwxrwx root root commons-codec.jar -> ../../../lib/commons-codec.jar
lrwxrwxrwx root root commons-io.jar -> ../../../lib/commons-io.jar
lrwxrwxrwx root root commons-lang3.jar -> ../../../lib/commons-lang3.jar
lrwxrwxrwx root root commons-logging.jar -> ../../../lib/commons-logging.jar
lrwxrwxrwx root root commons-net.jar -> ../../../lib/commons-net.jar
lrwxrwxrwx root root httpclient.jar -> ../../../lib/httpclient.jar
lrwxrwxrwx root root httpcore.jar -> ../../../lib/httpcore.jar
lrwxrwxrwx root root jackson-annotations.jar -> ../../../lib/jackson-annotations.jar
lrwxrwxrwx root root jackson-core.jar -> ../../../lib/jackson-core.jar
lrwxrwxrwx root root jackson-databind.jar -> ../../../lib/jackson-databind.jar
lrwxrwxrwx root root jackson-jaxrs-base.jar -> ../../../lib/jackson-jaxrs-base.jar
lrwxrwxrwx root root jackson-jaxrs-json-provider.jar -> ../../../lib/jackson-jaxrs-json-provider.jar
lrwxrwxrwx root root jackson-module-jaxb-annotations.jar -> ../../../lib/jackson-module-jaxb-annotations.jar
lrwxrwxrwx root root jakarta.activation-api.jar -> ../../../lib/jakarta.activation-api.jar
lrwxrwxrwx root root jakarta.annotation-api.jar -> ../../../lib/jakarta.annotation-api.jar
lrwxrwxrwx root root jakarta.xml.bind-api.jar -> ../../../lib/jakarta.xml.bind-api.jar
lrwxrwxrwx root root jboss-jaxrs-api_2.0_spec.jar -> ../../../lib/jboss-jaxrs-api_2.0_spec.jar
lrwxrwxrwx root root jboss-logging.jar -> ../../../lib/jboss-logging.jar
lrwxrwxrwx root root jss-tomcat-10.1.jar -> ../../../../../../usr/share/java/jss/jss-tomcat-10.1.jar
lrwxrwxrwx root root jss-tomcat.jar -> ../../../../../../usr/share/java/jss/jss-tomcat.jar
lrwxrwxrwx root root jss.jar -> ../../../lib/jss.jar
lrwxrwxrwx root root ldapjdk.jar -> ../../../lib/ldapjdk.jar
lrwxrwxrwx root root pki-common.jar -> ../../../lib/pki-common.jar
lrwxrwxrwx root root pki-tomcat-10.1.jar -> ../../../../../../usr/share/java/pki/pki-tomcat-10.1.jar
lrwxrwxrwx root root pki-tomcat.jar -> ../../../../../../usr/share/java/pki/pki-tomcat.jar
lrwxrwxrwx root root resteasy-jackson2-provider.jar -> ../../../lib/resteasy-jackson2-provider.jar
lrwxrwxrwx root root resteasy-jaxrs.jar -> ../../../lib/resteasy-jaxrs.jar
-rw-r--r-- root root resteasy-servlet-initializer-x.y.z.Final.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> resteasy-servlet-initializer-x.y.z.Final.jar
EOF

# normalize actual result:
# - replace version number with x.y.z
# - replace jss-tomcat-9.0.jar with jss-tomcat-10.1.jar
# - replace pki-tomcat-9.0.jar with pki-tomcat-10.1.jar
sed -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.jar$/-x.y.z.jar/' \
    -e 's/-[0-9]*\.[0-9]*\.[0-9]*\.Final\.jar$/-x.y.z.Final.jar/' \
    -e 's/jss-tomcat-9.0.jar/jss-tomcat-10.1.jar/g' \
    -e 's/pki-tomcat-9.0.jar/pki-tomcat-10.1.jar/g' \
    output > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server common lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI server lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root slf4j-api.jar -> ../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ROOT webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/ROOT \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root WEB-INF
-rw-r--r-- root root index.jsp
drwxr-xr-x root root jquery-3.5.1
drwxr-xr-x root root patternfly-4.35.2
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ROOT webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ROOT webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/ROOT/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ROOT webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/pki \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root WEB-INF
drwxr-xr-x root root admin
lrwxrwxrwx root root ca -> ../../../../../../usr/share/pki/common-ui/ca
lrwxrwxrwx root root css -> ../../../../../../usr/share/pki/common-ui/css
lrwxrwxrwx root root esc -> ../../../../../../usr/share/pki/common-ui/esc
lrwxrwxrwx root root fonts -> ../../../../../../usr/share/pki/common-ui/fonts
lrwxrwxrwx root root images -> ../../../../../../usr/share/pki/common-ui/images
-rw-r--r-- root root index.jsp
drwxr-xr-x root root js
lrwxrwxrwx root root kra -> ../../../../../../usr/share/pki/common-ui/kra
lrwxrwxrwx root root ocsp -> ../../../../../../usr/share/pki/common-ui/ocsp
lrwxrwxrwx root root pki.properties -> ../../../../../../usr/share/pki/common-ui/pki.properties
lrwxrwxrwx root root tks -> ../../../../../../usr/share/pki/common-ui/tks
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/pki/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/pki/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/server/webapps/pki/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-server-webapp.jar -> ../../../../../../../../usr/share/java/pki/pki-server-webapp.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ca/webapps/ca \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root 404.html
-rw-r--r-- root root 500.html
-rw-r--r-- root root GenUnexpectedError.template
drwxr-xr-x root root WEB-INF
drwxr-xr-x root root admin
drwxr-xr-x root root agent
drwxr-xr-x root root ee
-rw-r--r-- root root index.jsp
drwxr-xr-x root root js
-rw-r--r-- root root services.template
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ca/webapps/ca/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ca/webapps/ca/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ca/webapps/ca/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-ca.jar -> ../../../../../../../../usr/share/java/pki/pki-ca.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/kra/webapps/kra \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root 404.html
-rw-r--r-- root root 500.html
-rw-r--r-- root root GenUnexpectedError.template
drwxr-xr-x root root WEB-INF
drwxr-xr-x root root admin
drwxr-xr-x root root agent
-rw-r--r-- root root index.jsp
drwxr-xr-x root root js
-rw-r--r-- root root services.template
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/kra/webapps/kra/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/kra/webapps/kra/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/kra/webapps/kra/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-kra.jar -> ../../../../../../../../usr/share/java/pki/pki-kra.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ocsp/webapps/ocsp \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root 404.html
-rw-r--r-- root root 500.html
-rw-r--r-- root root GenUnexpectedError.template
drwxr-xr-x root root WEB-INF
drwxr-xr-x root root admin
drwxr-xr-x root root agent
-rw-r--r-- root root index.jsp
-rw-r--r-- root root services.template
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ocsp/webapps/ocsp/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ocsp/webapps/ocsp/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check OCSP webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/ocsp/webapps/ocsp/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-ocsp.jar -> ../../../../../../../../usr/share/java/pki/pki-ocsp.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check OCSP webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tks/webapps/tks \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root 404.html
-rw-r--r-- root root 500.html
-rw-r--r-- root root GenUnexpectedError.template
drwxr-xr-x root root WEB-INF
drwxr-xr-x root root admin
drwxr-xr-x root root agent
-rw-r--r-- root root index.jsp
-rw-r--r-- root root services.template
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tks/webapps/tks/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tks/webapps/tks/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TKS webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tks/webapps/tks/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root pki-tks.jar -> ../../../../../../../../usr/share/java/pki/pki-tks.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TKS webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tps/webapps/tps \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root 404.html
-rw-r--r-- root root 500.html
-rw-r--r-- root root GenUnexpectedError.template
drwxr-xr-x root root WEB-INF
-rw-r--r-- root root index.jsp
drwxr-xr-x root root js
drwxr-xr-x root root ui
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tps/webapps/tps/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check TPS webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/tps/webapps/tps/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root pki-tps.jar -> ../../../../../../../../usr/share/java/pki/pki-tps.jar
lrwxrwxrwx root root resteasy-servlet-initializer.jar -> ../../../../../server/common/lib/resteasy-servlet-initializer.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check TPS webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/acme/webapps/acme \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root WEB-INF
-rw-r--r-- root root config.jsp
-rw-r--r-- root root home.jsp
-rw-r--r-- root root index.jsp
drwxr-xr-x root root js
-rw-r--r-- root root services.jsp
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/acme/webapps/acme/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/acme/webapps/acme/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check ACME webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/acme/webapps/acme/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-acme.jar -> ../../../../../../../../usr/share/java/pki/pki-acme.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check ACME webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST webapp dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/est/webapps/est \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root WEB-INF
-rw-r--r-- root root index.jsp
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST webapp dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST webapp WEB-INF dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/est/webapps/est/WEB-INF \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
drwxr-xr-x root root classes
drwxr-xr-x root root lib
-rw-r--r-- root root web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST webapp WEB-INF dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST webapp WEB-INF/classes dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/est/webapps/est/WEB-INF/classes \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
-rw-r--r-- root root logging.properties
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST webapp WEB-INF/classes dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check EST webapp WEB-INF/lib dir"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /usr/share/pki/est/webapps/est/WEB-INF/lib \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

cat > expected << EOF
lrwxrwxrwx root root pki-est.jar -> ../../../../../../../../usr/share/java/pki/pki-est.jar
lrwxrwxrwx root root pki-server.jar -> ../../../../../../../../usr/share/java/pki/pki-server.jar
lrwxrwxrwx root root slf4j-api.jar -> ../../../../../lib/slf4j-api.jar
lrwxrwxrwx root root slf4j-jdk14.jar -> ../../../../../lib/slf4j-jdk14.jar
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check EST webapp WEB-INF/lib dir (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server
docker exec pki pki-server --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI version"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server --version

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI version (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI with wrong option"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server --wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI with wrong option (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server CLI with wrong sub-command"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server wrong \
    > >(tee stdout) 2> >(tee stderr >&2) || true

cat > expected << EOF
ERROR: Invalid module "wrong".
EOF

diff expected stderr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server CLI with wrong sub-command (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-server create CLI help message"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create --help

# TODO: validate output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-server create CLI help message (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create pki-tomcat server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create pki-tomcat server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start pki-tomcat server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server start --wait -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start pki-tomcat server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server base dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
lrwxrwxrwx pkiuser pkiuser bin -> /usr/share/tomcat/bin
drwxr-x--- pkiuser pkiuser common
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/lib
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
drwxr-x--- pkiuser pkiuser temp
drwxr-x--- pkiuser pkiuser webapps
drwxr-x--- pkiuser pkiuser work
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server base dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server common dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat/common \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
lrwxrwxrwx pkiuser pkiuser lib -> /usr/share/pki/server/common/lib
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server common dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server conf dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
drwxr-x--- pkiuser pkiuser Catalina
-rw-rw---- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxr-x--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server conf dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server.xml"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server.xml (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check pki-tomcat tomcat.conf"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /etc/pki/pki-tomcat/tomcat.conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat tomcat.conf (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server conf/Catalina/localhost dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat/Catalina/localhost \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
lrwxrwxrwx pkiuser pkiuser rewrite.config -> /usr/share/pki/server/conf/Catalina/localhost/rewrite.config
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server conf/Catalina/localhost dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat webapps"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server webapp-find | tee output

# there should be no webapps
sed -n 's/^ *Webapp ID: *\(.*\)$/\1/p' output > actual
diff /dev/null actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat webapps (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat subsystems"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server subsystem-find | tee output

# there should be no subsystems
sed -n 's/^ *Subsystem ID: *\(.*\)$/\1/p' output > actual
diff /dev/null actual

# CA subsystem should not exist
docker exec pki pki-server subsystem-show ca \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "ERROR: No ca subsystem in instance pki-tomcat." > expected
diff expected stderr

# create empty CA subsystem folder
docker exec pki mkdir -p /var/lib/pki/pki-tomcat/ca

# CA subsystem should not exist
docker exec pki pki-server subsystem-show ca \
    > >(tee stdout) 2> >(tee stderr >&2) || true

echo "ERROR: No ca subsystem in instance pki-tomcat." > expected
diff expected stderr

# remove CA subsystem folder
docker exec pki rm -rf /var/lib/pki/pki-tomcat/ca
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat subsystems (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check HTTP connection to pki-tomcat server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    http://pki.example.com:8080
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTP connection to pki-tomcat server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop pki-tomcat server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server stop --wait -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop pki-tomcat server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove pki-tomcat server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server remove -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove pki-tomcat server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server base dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
lrwxrwxrwx pkiuser pkiuser conf -> /etc/pki/pki-tomcat
lrwxrwxrwx pkiuser pkiuser logs -> /var/log/pki/pki-tomcat
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server base dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server conf dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /etc/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
drwxr-x--- pkiuser pkiuser Catalina
-rw-rw---- pkiuser pkiuser catalina.policy
lrwxrwxrwx pkiuser pkiuser catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxr-x--- pkiuser pkiuser certs
lrwxrwxrwx pkiuser pkiuser context.xml -> /etc/tomcat/context.xml
lrwxrwxrwx pkiuser pkiuser logging.properties -> /usr/share/pki/server/conf/logging.properties
-rw-rw---- pkiuser pkiuser server.xml
-rw-rw---- pkiuser pkiuser tomcat.conf
lrwxrwxrwx pkiuser pkiuser web.xml -> /etc/tomcat/web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server conf dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost.$DATE.log
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check pki-tomcat server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/log/pki/pki-tomcat \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r--r-- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxr-x--- pkiuser pkiuser backup
-rw-r----- pkiuser pkiuser localhost_access_log.$DATE.txt
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check pki-tomcat server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create tomcat@pki server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server create tomcat@pki -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create tomcat@pki server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Start tomcat@pki server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
#Disabling test for new tomcat 10
if [ $TOMCAT_FLAVOR != 'new' ]; then
   docker exec pki pki-server start tomcat@pki --wait -v
fi
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Start tomcat@pki server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server base dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
lrwxrwxrwx tomcat tomcat bin -> /usr/share/tomcat/bin
drwxr-x--- tomcat tomcat common
drwxr-x--- tomcat tomcat conf
lrwxrwxrwx tomcat tomcat lib -> /usr/share/pki/server/lib
drwxr-x--- tomcat tomcat logs
drwxr-x--- tomcat tomcat temp
drwxr-x--- tomcat tomcat webapps
drwxr-x--- tomcat tomcat work
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server base dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server conf dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
drwxr-x--- tomcat tomcat Catalina
-rw-rw---- tomcat tomcat catalina.policy
lrwxrwxrwx tomcat tomcat catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxr-x--- tomcat tomcat certs
lrwxrwxrwx tomcat tomcat context.xml -> /etc/tomcat/context.xml
-rw-rw---- tomcat tomcat logging.properties
-rw-rw---- tomcat tomcat server.xml
-rw-rw---- tomcat tomcat tomcat.conf
lrwxrwxrwx tomcat tomcat web.xml -> /etc/tomcat/web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server conf dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server.xml"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /var/lib/tomcats/pki/conf/server.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server.xml (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tomcat@pki tomcat.conf"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki cat /var/lib/tomcats/pki/conf/tomcat.conf
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki tomcat.conf (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check tomcat@pki server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxr-x--- tomcat tomcat backup
-rw-r--r-- tomcat tomcat catalina.$DATE.log
-rw-r--r-- tomcat tomcat host-manager.$DATE.log
-rw-r--r-- tomcat tomcat localhost.$DATE.log
-rw-r--r-- tomcat tomcat localhost_access_log.$DATE.txt
-rw-r--r-- tomcat tomcat manager.$DATE.log
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server logs dir after installation"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxr-x--- tomcat tomcat backup
-rw-r--r-- tomcat tomcat catalina.$DATE.log
-rw-r--r-- tomcat tomcat localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxr-x--- tomcat tomcat backup
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server logs dir after installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check HTTP connection to tomcat@pki server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail

if [ $TOMCAT_FLAVOR == 'old' ]; then
docker exec pki curl \
    --retry 60 \
    --retry-delay 0 \
    --retry-connrefused \
    -s \
    -k \
    -o /dev/null \
    http://pki.example.com:8080
fi
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTP connection to tomcat@pki server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Stop tomcat@pki server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
if [ $TOMCAT_FLAVOR == 'old' ]; then
docker exec pki pki-server stop tomcat@pki --wait -v
fi
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Stop tomcat@pki server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove tomcat@pki server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server remove tomcat@pki -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove tomcat@pki server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server base dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
drwxr-x--- tomcat tomcat conf
drwxr-x--- tomcat tomcat logs
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server base dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server conf dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/conf \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

# TODO: review permissions
cat > expected << EOF
drwxr-x--- tomcat tomcat Catalina
-rw-rw---- tomcat tomcat catalina.policy
lrwxrwxrwx tomcat tomcat catalina.properties -> /usr/share/pki/server/conf/catalina.properties
drwxr-x--- tomcat tomcat certs
lrwxrwxrwx tomcat tomcat context.xml -> /etc/tomcat/context.xml
-rw-rw---- tomcat tomcat logging.properties
-rw-rw---- tomcat tomcat server.xml
-rw-rw---- tomcat tomcat tomcat.conf
lrwxrwxrwx tomcat tomcat web.xml -> /etc/tomcat/web.xml
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server conf dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -lt 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected << EOF
drwxr-x--- tomcat tomcat backup
-rw-r--r-- tomcat tomcat catalina.$DATE.log
-rw-r--r-- tomcat tomcat host-manager.$DATE.log
-rw-r--r-- tomcat tomcat localhost.$DATE.log
-rw-r--r-- tomcat tomcat localhost_access_log.$DATE.txt
-rw-r--r-- tomcat tomcat manager.$DATE.log
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check tomcat@pki server logs dir after removal"
if [[ "$GHA_FAILED" -eq 0 ]] && [[ "${FEDORA_VERSION}" -ge 43 ]]; then
set +e
(
set -euo pipefail
# check file types, owners, and permissions
docker exec pki ls -l /var/lib/tomcats/pki/logs \
    | sed \
        -e '/^total/d' \
        -e 's/^\(\S*\)\./\1/' \
        -e 's/^\(\S*\) *\S* *\(\S*\) *\(\S*\) *\S* *\S* *\S* *\S* *\(.*\)$/\1 \2 \3 \4/' \
    | tee output

DATE=$(date +'%Y-%m-%d')

# TODO: review permissions
cat > expected_old << EOF
drwxr-x--- tomcat tomcat backup
-rw-r--r-- tomcat tomcat catalina.$DATE.log
-rw-r--r-- tomcat tomcat localhost_access_log.$DATE.txt
EOF

cat > expected_new << EOF
drwxr-x--- tomcat tomcat backup
EOF

diff expected_$TOMCAT_FLAVOR output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check tomcat@pki server logs dir after removal (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== server-basic-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== server-basic-test PASSED ===="
