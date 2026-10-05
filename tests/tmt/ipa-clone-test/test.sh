#!/bin/bash
# Generated TMT port of .github/workflows/ipa-clone-test.yml
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
    docker rm -f primary secondary 2>/dev/null || true
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

step "Retrieve IPA images"
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
    echo "FAIL: Retrieve IPA images (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Load IPA images"
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
    echo "FAIL: Load IPA images (rc=$_rc)" >&2
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

step "Run primary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --image=ipa-runner \
    --hostname=primary.example.com \
    --network=example \
    --network-alias=primary.example.com \
    --network-alias=ipa-ca.example.com \
    primary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA server in primary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary sysctl net.ipv6.conf.lo.disable_ipv6=0
docker exec primary ipa-server-install \
    -U \
    --domain example.com \
    -r EXAMPLE.COM \
    -p Secret.123 \
    -a Secret.123 \
    --no-host-dns \
    --no-ntp
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA server in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update primary PKI server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary dnf install -y xmlstarlet

# disable access log buffer
docker exec primary xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart PKI server
docker exec primary pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update primary PKI server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config in primary IPA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=o=ipaca
internaldb.database=ipaca
internaldb.ldapauth.authtype=SslClientAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=subsystemCert cert-pki-ca
internaldb.ldapconn.host=primary.example.com
internaldb.ldapconn.port=636
internaldb.ldapconn.secureConn=true
internaldb.maxConns=15
internaldb.minConns=3
internaldb.multipleSuffix.enable=false
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA database config in primary IPA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CRL config in primary IPA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-config-find | grep ca.crl.MasterCRL

# CRL cache should be enabled
echo "true" > expected
docker exec primary pki-server ca-config-show ca.crl.MasterCRL.enableCRLCache | tee actual
diff expected actual

# CRL updates should be enabled
echo "true" > expected
docker exec primary pki-server ca-config-show ca.crl.MasterCRL.enableCRLUpdates | tee actual
diff expected actual

# CA should listen to clone modifications
echo "true" > expected
docker exec primary pki-server ca-config-show ca.listenToCloneModifications | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CRL config in primary IPA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary IPA server config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo Secret.123 | docker exec -i primary kinit admin
docker exec primary klist

docker exec primary ipa config-show | tee output

# primary server should be IPA master
echo "primary.example.com" > expected
sed -n -e 's/^ *IPA masters: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# primary server should have CA
echo "primary.example.com" > expected
sed -n -e 's/^ *IPA CA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# primary server should be the renewal master
echo "primary.example.com" > expected
sed -n -e 's/^ *IPA CA renewal master: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary IPA server config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in primary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ipa-kra-install -p Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server cert-export \
    --cert-file $SHARED/kra_transport.crt \
    kra_transport

TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec primary pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be enabled and point to primary KRA
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=primary.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystemCert cert-pki-ca
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec primary pki-server ca-connector-find | tee output

# KRA connector should be enabled and point to primary KRA
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://primary.example.com:8443
  Nickname: subsystemCert cert-pki-ca
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary IPA server config after KRA installation"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ipa config-show | tee output

# primary servers should have KRA
echo "primary.example.com" > expected
sed -n -e 's/^ *IPA KRA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary IPA server config after KRA installation (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
tests/bin/runner-init.sh \
    --image=ipa-runner \
    --hostname=secondary.example.com \
    --network=example \
    --network-alias=secondary.example.com \
    secondary
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Run secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install IPA client in secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary sysctl net.ipv6.conf.lo.disable_ipv6=0
docker exec secondary ipa-client-install \
    -U \
    --server=primary.example.com \
    --domain=example.com \
    --realm=EXAMPLE.COM \
    -p admin \
    -w Secret.123 \
    --no-ntp

echo Secret.123 | docker exec -i secondary kinit admin
docker exec secondary klist

docker exec secondary ipa config-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install IPA client in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Promote IPA client into IPA replica in secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# install basic IPA replica (without CA and KRA)
docker exec secondary ipa-replica-install --no-host-dns

docker exec secondary ipa config-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Promote IPA client into IPA replica in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA in secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa-ca-install -p Secret.123

docker exec secondary ipa config-show
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Update secondary PKI server configuration"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary dnf install -y xmlstarlet

# disable access log buffer
docker exec secondary xmlstarlet edit --inplace \
    -u "//Valve[@className='org.apache.catalina.valves.AccessLogValve']/@buffered" \
    -v "false" \
    -i "//Valve[@className='org.apache.catalina.valves.AccessLogValve' and not(@buffered)]" \
    -t attr \
    -n "buffered" \
    -v "false" \
    /etc/pki/pki-tomcat/server.xml

# restart PKI server
docker exec secondary pki-server restart --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Update secondary PKI server configuration (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA database config in secondary IPA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-config-find | grep "^internaldb\." | tee output

cat > expected << EOF
internaldb._000=##
internaldb._001=## Internal Database
internaldb._002=##
internaldb.basedn=o=ipaca
internaldb.database=ipaca
internaldb.ldapauth.authtype=SslClientAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapauth.clientCertNickname=subsystemCert cert-pki-ca
internaldb.ldapconn.host=secondary.example.com
internaldb.ldapconn.port=636
internaldb.ldapconn.secureConn=true
internaldb.maxConns=15
internaldb.minConns=3
internaldb.multipleSuffix.enable=false
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA database config in secondary IPA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CRL config in primary IPA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-config-find | grep ca.crl.MasterCRL

# CRL cache should be enabled
echo "true" > expected
docker exec primary pki-server ca-config-show ca.crl.MasterCRL.enableCRLCache | tee actual
diff expected actual

# CRL updates should be enabled
echo "true" > expected
docker exec primary pki-server ca-config-show ca.crl.MasterCRL.enableCRLUpdates | tee actual
diff expected actual

# CA should listen to clone modifications
echo "true" > expected
docker exec primary pki-server ca-config-show ca.listenToCloneModifications | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CRL config in primary IPA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CRL config in secondary IPA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-config-find | grep ca.crl.MasterCRL

# CRL cache should be disabled
echo "false" > expected
docker exec secondary pki-server ca-config-show ca.crl.MasterCRL.enableCRLCache | tee actual
diff expected actual

# CRL updates should be disabled
echo "false" > expected
docker exec secondary pki-server ca-config-show ca.crl.MasterCRL.enableCRLUpdates | tee actual
diff expected actual

# CA should not listen to clone modifications
echo "false" > expected
docker exec secondary pki-server ca-config-show ca.listenToCloneModifications | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CRL config in secondary IPA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install KRA in secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa-kra-install -p Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install KRA in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check schema in primary DS and secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses attributeTypes \
    | grep "\-oid" | sort | tee primary.schema

docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b cn=schema \
    -o ldif_wrap=no \
    -LLL \
    objectClasses attributeTypes \
    | grep "\-oid" | sort | tee secondary.schema

diff primary.schema secondary.schema
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check schema in primary DS and secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication managers on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=config" \
    -o ldif_wrap=no \
    -LLL \
    "(cn=replication manager)"

docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replication managers,cn=sysaccounts,cn=etc,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication managers on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication managers on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=config" \
    -o ldif_wrap=no \
    -LLL \
    "(cn=replication manager)"

docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replication managers,cn=sysaccounts,cn=etc,dc=example,dc=com" \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication managers on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica objects on primary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=o\3Dipaca,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica objects on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replica objects on secondary DS"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=dc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=replica,cn=o\3Dipaca,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replica objects on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check replication agreements on primary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=meTosecondary.example.com,cn=replica,cn=dc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

docker exec primary ldapsearch \
    -H ldap://primary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=caTosecondary.example.com,cn=replica,cn=o\3Dipaca,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication agreements on primary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check replication agreements on secondary DS"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=meToprimary.example.com,cn=replica,cn=dc\3Dexample\2Cdc\3Dcom,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL

docker exec secondary ldapsearch \
    -H ldap://secondary.example.com:389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -x \
    -b "cn=caToprimary.example.com,cn=replica,cn=o\3Dipaca,cn=mapping tree,cn=config" \
    -s base \
    -o ldif_wrap=no \
    -LLL
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check replication agreements on secondary DS (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector config in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec primary pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be enabled and point to primary KRA
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=primary.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystemCert cert-pki-ca
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec primary pki-server ca-connector-find | tee output

# KRA connector should be enabled and point to primary KRA
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://primary.example.com:8443
  Nickname: subsystemCert cert-pki-ca
EOF

diff expected output
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector config in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec secondary pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should be enabled and point to both KRAs
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=primary.example.com:8443 secondary.example.com:8443
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystemCert cert-pki-ca
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

diff expected output

docker exec secondary pki-server ca-connector-find | tee output

# KRA connector should be enabled and point to both KRAs
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://primary.example.com:8443 https://secondary.example.com:8443
  Nickname: subsystemCert cert-pki-ca
EOF

diff expected output

# KRA connectors should be consistent
# https://pagure.io/freeipa/issue/9432
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check IPA server config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ipa config-show | tee output

# both servers should be IPA masters
echo "primary.example.com, secondary.example.com" > expected
sed -n -e 's/^ *IPA masters: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# both servers should have CA
echo "primary.example.com, secondary.example.com" > expected
sed -n -e 's/^ *IPA CA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# both servers should have KRA
echo "primary.example.com, secondary.example.com" > expected
sed -n -e 's/^ *IPA KRA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# primary server should be the renewal master
echo "primary.example.com" > expected
sed -n -e 's/^ *IPA CA renewal master: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA server config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change renewal master"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg before renewal update
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.orig
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary.orig

# move renewal master to secondary server
docker exec primary ipa config-mod \
    --ca-renewal-master-server secondary.example.com

docker exec primary ipa config-show | tee output

# secondary server should be the renewal master
echo "secondary.example.com" > expected
sed -n -e 's/^ *IPA CA renewal master: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change renewal master (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check primary CA config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after-renewal-update

# renewal config is maintained by IPA, so there should be no change in PKI
diff CS.cfg.primary.orig CS.cfg.primary.after-renewal-update
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check primary CA config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check secondary CA config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary.after-renewal-update

# renewal config is maintained by IPA, so there should be no change in PKI
diff CS.cfg.secondary.orig CS.cfg.secondary.after-renewal-update
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check secondary CA config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA CSR copied correctly"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker cp primary:/var/lib/pki/pki-tomcat/conf/certs primary-certs
docker cp secondary:/var/lib/pki/pki-tomcat/conf/certs secondary-certs

diff primary-certs/ca_audit_signing.csr secondary-certs/ca_audit_signing.csr
diff primary-certs/ca_ocsp_signing.csr secondary-certs/ca_ocsp_signing.csr
diff primary-certs/ca_signing.csr secondary-certs/ca_signing.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA CSR copied correctly (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL generation config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ipa-crlgen-manage status | tee output

# CRL generation should be enabled in primary CA
echo "enabled" > expected
sed -n -e 's/^ *CRL generation: *\(.*\)$/\1/p' output | tee actual
diff expected actual

docker exec secondary ipa-crlgen-manage status | tee output

# CRL generation should be disabled in secondary CA
echo "disabled" > expected
sed -n -e 's/^ *CRL generation: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL generation config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Change CRL master"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# move CRL generation to secondary server
docker exec primary ipa-crlgen-manage disable
docker exec secondary ipa-crlgen-manage enable

docker exec primary ipa-crlgen-manage status | tee output

# CRL generation should be disabled on the primary server
echo "disabled" > expected
sed -n -e 's/^ *CRL generation: *\(.*\)$/\1/p' output | tee actual
diff expected actual

docker exec secondary ipa-crlgen-manage status | tee output

# CRL generation should be enabled on the secondary server
echo "enabled" > expected
sed -n -e 's/^ *CRL generation: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Change CRL master (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL generation config in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from primary CA after CRL generation update
docker cp primary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.primary.after-crl-update

docker exec primary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - CRL, cache, and updates should be disabled in primary CA
sed -e 's/^\(ca.crl.MasterCRL.enable\)=.*$/\1=false/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLCache\)=.*$/\1=false/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLUpdates\)=.*$/\1=false/' \
    -e 's/^\(ca.listenToCloneModifications\)=.*$/\1=false/' \
    -e '$ a ca.certStatusUpdateInterval=0' \
    CS.cfg.primary.after-renewal-update \
    | sort > expected

# normalize actual result
# - temporarily change ca.crl.MasterCRL.enable to false
#   TODO: remove this change once the following PR is merged:
#   https://github.com/freeipa/freeipa/pull/6971
sed -e 's/^\(ca.crl.MasterCRL.enable\)=.*$/\1=false/' \
    CS.cfg.primary.after-crl-update \
    | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL generation config in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL generation config in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# get CS.cfg from secondary CA after CRL generation update
docker cp secondary:/var/lib/pki/pki-tomcat/conf/ca/CS.cfg CS.cfg.secondary.after-crl-update

docker exec secondary pki-server ca-config-find | grep ca.crl.MasterCRL

# normalize expected result:
# - CRL, cache, and updates should be enabled in secondary CA
sed -e 's/^\(ca.crl.MasterCRL.enable\)=.*$/\1=true/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLCache\)=.*$/\1=true/' \
    -e 's/^\(ca.crl.MasterCRL.enableCRLUpdates\)=.*$/\1=true/' \
    -e 's/^\(ca.listenToCloneModifications\)=.*$/\1=true/' \
    CS.cfg.secondary.after-renewal-update \
    | sort > expected

# normalize actual result
sed -e '$ a ca.certStatusUpdateInterval=0' \
    CS.cfg.secondary.after-crl-update | sort > actual

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL generation config in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in primary container"
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
    docker exec primary pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Run PKI healthcheck in secondary container"
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
    docker exec secondary pki-healthcheck --failures-only
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
    echo "FAIL: Run PKI healthcheck in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI database user in primary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary pki-server ca-user-show \
    --attr nsPagedSizeLimit \
    --attr nsPagedLookThroughLimit \
    pkidbuser \
    | tee output

cat > expected << EOF
  User ID: pkidbuser
  Full Name: pkidbuser
  Type: agentType
  State: 1
  nsPagedSizeLimit: -1
EOF

diff expected output

docker exec primary pki-server ca-user-cert-find pkidbuser
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI database user in primary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check PKI database user in secondary CA"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary pki-server ca-user-show \
    --attr nsPagedSizeLimit \
    --attr nsPagedLookThroughLimit \
    pkidbuser \
    | tee output

cat > expected << EOF
  User ID: pkidbuser
  Full Name: pkidbuser
  Type: agentType
  State: 1
  nsPagedSizeLimit: -1
EOF

diff expected output

docker exec secondary pki-server ca-user-cert-find pkidbuser
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI database user in secondary CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Verify CA admin"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary cp /root/ca-agent.p12 ${SHARED}/ca-agent.p12
docker exec secondary pki-server cert-export ca_signing --cert-file ca_signing.crt

docker exec secondary pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec secondary pki pkcs12-import \
    --pkcs12 ${SHARED}/ca-agent.p12 \
    --pkcs12-password Secret.123
docker exec secondary pki -n ipa-ca-agent \
    ca-user-show admin
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Verify CA admin (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check subca replication from primary"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec primary ipa ca-add subca --subject cn=subca,O=EXAMPLE.COM
docker exec primary ipa ca-find | tee output-primary
docker exec secondary ipa ca-find | tee output-secondary
diff output-primary output-secondary
echo "Number of entries returned 2" > expected
grep "Number of entries returned" output-secondary > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check subca replication from primary (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove subca from clone"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa ca-disable subca
docker exec secondary ipa ca-del subca
docker exec secondary ipa ca-find | tee output-secondary
docker exec primary ipa ca-find | tee output-primary
diff output-primary output-secondary
echo "Number of entries returned 1" > expected
grep "Number of entries returned" output-primary > actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove subca from clone (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check IPA CA install log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/ipaserver-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA CA install log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check IPA KRA install log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/ipaserver-kra-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA KRA install log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD access logs in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/httpd/access_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD access logs in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD error logs in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/httpd/error_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD error logs in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS server systemd journal in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u dirsrv@EXAMPLE-COM.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server systemd journal in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS access logs in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/dirsrv/slapd-EXAMPLE-COM/access
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS access logs in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS error logs in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/dirsrv/slapd-EXAMPLE-COM/errors
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS error logs in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS security logs in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary cat /var/log/dirsrv/slapd-EXAMPLE-COM/security
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS security logs in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA pkispawn log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki -name "pki-ca-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkispawn log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA pkispawn log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki -name "pki-kra-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkispawn log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server systemd journal in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server access log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove IPA server from primary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa server-del primary.example.com
docker exec primary ipa-server-install --uninstall -U
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove IPA server from primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA pkidestroy log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki -name "pki-ca-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkidestroy log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA pkidestroy log in primary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec primary find /var/log/pki -name "pki-kra-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkidestroy log in primary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check IPA config after removing primary server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa config-show | tee output

# secondary server should be IPA master
echo "secondary.example.com" > expected
sed -n -e 's/^ *IPA masters: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# CA should only be available on secondary server
echo "secondary.example.com" > expected
sed -n -e 's/^ *IPA CA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# KRA should only be available on secondary server
echo "secondary.example.com" > expected
sed -n -e 's/^ *IPA KRA servers: *\(.*\)$/\1/p' output | tee actual
diff expected actual

# secondary server should be the renewal master
echo "secondary.example.com" > expected
sed -n -e 's/^ *IPA CA renewal master: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA config after removing primary server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CRL generator after removing primary server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa-crlgen-manage status | tee output

# CRL generation should be enabled on the secondary server
echo "enabled" > expected
sed -n -e 's/^ *CRL generation: *\(.*\)$/\1/p' output | tee actual
diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CRL generator after removing primary server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check KRA connector after removing primary server"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
TRANSPORT_CERT=$(openssl x509 \
    -in kra_transport.crt \
    -outform der \
    | base64 --wrap=0)

docker exec secondary pki-server ca-config-find | grep ^ca\.connector.KRA\. | tee output

# KRA connector should point to secondary KRA
cat > expected << EOF
ca.connector.KRA.enable=true
ca.connector.KRA.host=secondary.example.com
ca.connector.KRA.local=false
ca.connector.KRA.nickName=subsystemCert cert-pki-ca
ca.connector.KRA.port=8443
ca.connector.KRA.timeout=30
ca.connector.KRA.transportCert=$TRANSPORT_CERT
ca.connector.KRA.uri=/kra/agent/kra/connector
EOF

# currently it still points to both KRAs
# https://pagure.io/freeipa/issue/9432
diff expected output || true

docker exec secondary pki-server ca-connector-find | tee output

# KRA connector should point to secondary KRA
cat > expected << EOF
  Connector ID: KRA
  Enabled: true
  URL: https://secondary.example.com:8443
  Nickname: subsystemCert cert-pki-ca
EOF

# currently it still points to both KRAs
# https://pagure.io/freeipa/issue/9432
diff expected output || true
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA connector after removing primary server (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check IPA CA install log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/ipareplica-ca-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA CA install log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check IPA KRA install log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/ipaserver-kra-install.log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check IPA KRA install log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD access logs in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/httpd/access_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD access logs in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check HTTPD error logs in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/httpd/error_log
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check HTTPD error logs in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS server systemd journal in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u dirsrv@EXAMPLE-COM.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS server systemd journal in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS access logs in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/dirsrv/slapd-EXAMPLE-COM/access
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS access logs in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS error logs in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/dirsrv/slapd-EXAMPLE-COM/errors
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS error logs in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check DS security logs in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary cat /var/log/dirsrv/slapd-EXAMPLE-COM/security
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check DS security logs in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA pkispawn log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki -name "pki-ca-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkispawn log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA pkispawn log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki -name "pki-kra-spawn.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkispawn log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server systemd journal in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary journalctl -x --no-pager -u pki-tomcatd@pki-tomcat.service
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server systemd journal in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check PKI server access log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check CA debug log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/lib/pki/pki-tomcat/logs/ca -name "debug.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA debug log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Remove IPA server from secondary container"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec secondary ipa-server-install --uninstall -U --ignore-last-of-role
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove IPA server from secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check CA pkidestroy log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki -name "pki-ca-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check CA pkidestroy log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

step "Check KRA pkidestroy log in secondary container"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec secondary find /var/log/pki -name "pki-kra-destroy.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check KRA pkidestroy log in secondary container (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi

if [[ "$GHA_FAILED" -ne 0 ]]; then
    echo "==== ipa-clone-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ipa-clone-test PASSED ===="
