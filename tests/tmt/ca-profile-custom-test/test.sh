#!/bin/bash
# Generated TMT port of .github/workflows/ca-profile-custom-test.yml
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

step "Install dependencies"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# GHA: apt-get install — on Fedora/TMT runner these are available or use dnf
# Packages needed: xmlstarlet
# Most are available in the pki-runner container or Fedora host.
command -v xmlstarlet >/dev/null 2>&1 || dnf install -y xmlstarlet 2>/dev/null || true
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

step "Set up authentication database"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec -i ds ldapadd \
    -H ldap://ds.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 << EOF
dn: ou=people,dc=example,dc=com
objectclass: top
objectclass: organizationalUnit
ou: People
aci: (target = "ldap:///ou=people,dc=example,dc=com")
 (targetattr=objectClass||dc||ou||uid||cn||sn||givenName)
 (version 3.0; acl "Allow anyone to read and search basic attributes"; allow (search, read) userdn = "ldap:///anyone";)
aci: (target = "ldap:///ou=people,dc=example,dc=com")
 (targetattr=*)
 (version 3.0; acl "Allow anyone to read and search itself"; allow (search, read) userdn = "ldap:///self";)

dn: uid=testuser,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser
cn: 鄧麗君
sn: 鄧
userPassword: Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Set up authentication database (rc=$_rc)" >&2
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
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    -v
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Configure UserDirEnrollment"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.pluginName UidPwdDirAuth
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.basedn dc=example,dc=com
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapauth.authtype BasicAuth
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapauth.bindDN "cn=Directory Manager"
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapauth.bindPWPrompt internaldb
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapconn.host ds.example.com
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapconn.port 3389
docker exec pki pki-server ca-config-set auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn false
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Configure UserDirEnrollment (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Restart CA subsystem"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server ca-redeploy --wait
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Restart CA subsystem (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Install CA admin cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki-server cert-export \
    --cert-file ca_signing.crt \
    ca_signing

docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing

docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --password Secret.123
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Install CA admin cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Retrieve caDirUserCert profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-show \
    --output $SHARED/CustomProfile.xml \
    caDirUserCert

cat CustomProfile.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Retrieve caDirUserCert profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create custom profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
# allow updates
sudo chmod go+w CustomProfile.xml

# update profile ID
xmlstarlet edit --inplace \
    -u "/Profile/@id" \
    -v "CustomProfile" \
    CustomProfile.xml

# update profile name
xmlstarlet edit --inplace \
    -u "/Profile/name" \
    -v "中文 Cert Profile" \
    CustomProfile.xml

# update profile description
xmlstarlet edit --inplace \
    -u "/Profile/description" \
    -v "Certificate profile in 中文" \
    CustomProfile.xml

cat CustomProfile.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create custom profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Add custom profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-add \
    $SHARED/CustomProfile.xml
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Add custom profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Enable custom profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-enable \
    CustomProfile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Enable custom profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check custom profile info"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-show \
    CustomProfile \
    | tee output

sed -n \
    -e "/^\s*Name:/p" \
    -e "/^\s*Description:/p" \
    output > actual

cat > expected << EOF
  Name: 中文 Cert Profile
  Description: Certificate profile in 中文
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check custom profile info (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check custom profile config"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-show \
    --raw \
    CustomProfile \
    | tee output

sed -n \
    -e "/^name=/p" \
    -e "/^desc=/p" \
    output > actual

cat > expected << EOF
desc=Certificate profile in 中文
name=中文 Cert Profile
EOF
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check custom profile config (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Check custom profile config file"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki cat /var/lib/pki/pki-tomcat/ca/profiles/ca/CustomProfile.cfg \
    | tee output

sed -n \
    -e "/^name=/p" \
    -e "/^desc=/p" \
    output > actual

cat > expected << EOF
desc=Certificate profile in 中文
name=中文 Cert Profile
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check custom profile config file (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Create cert request"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki nss-cert-request \
    --subject "UID=testuser,OU=people,DC=example,DC=com" \
    --csr testuser.csr
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Create cert request (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Issue cert"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
echo "Secret.123" > password.txt

docker exec pki pki ca-cert-issue \
    --profile CustomProfile \
    --username testuser \
    --password-file $SHARED/password.txt \
    --csr-file testuser.csr \
    --output-file testuser.crt

# import cert
docker exec pki pki nss-cert-import testuser --cert testuser.crt
docker exec pki pki nss-cert-show testuser | tee output

# normalize output
sed \
    -e '/^ *Serial Number:/d' \
    -e '/^ *Not Valid Before:/d' \
    -e '/^ *Not Valid After:/d' \
    output > actual

cat > expected << EOF
  Nickname: testuser
  Subject DN: UID=testuser,OU=people,DC=example,DC=com
  Issuer DN: CN=CA Signing Certificate,OU=pki-tomcat,O=EXAMPLE
  Trust Flags: u,u,u
EOF

diff expected actual
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Issue cert (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Disable custom profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-disable \
    CustomProfile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Disable custom profile (rc=$_rc)" >&2
    GHA_FAILED=$_rc
fi
fi

step "Remove custom profile"
if [[ "$GHA_FAILED" -eq 0 ]]; then
set +e
(
set -euo pipefail
docker exec pki pki \
    -n caadmin \
    ca-profile-del \
    CustomProfile
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Remove custom profile (rc=$_rc)" >&2
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

step "Check PKI server access log"
# GHA if: always() — run even after prior step failures; may fail the test
set +e
(
set -euo pipefail
docker exec pki find /var/log/pki/pki-tomcat -name "localhost_access_log.*" -exec cat {} \;
)
_rc=$?
set -euo pipefail
if [[ $_rc -ne 0 ]]; then
    echo "FAIL: Check PKI server access log (rc=$_rc)" >&2
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
    echo "==== ca-profile-custom-test FAILED ===="
    exit "$GHA_FAILED"
fi
echo "==== ca-profile-custom-test PASSED ===="
