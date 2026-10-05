        # Basic ACME

        TMT port of `.github/workflows/acme-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Check pki acme CLI help message
- Install CA in PKI container
- Install CA admin cert
- Check initial CA certs
- Install ACME in PKI container
- Check for warnings
- Check external commands
- Get Tomcat flavor
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check ACME base dir
- Check ACME conf dir
- Check ACME database config
- Check ACME issuer config
- Check ACME realm config
- Check ACME logs dir
- Initialize ACME database
- Initialize ACME realm
- Check initial ACME accounts
- Check initial ACME orders
- Check initial ACME authorizations
- Check initial ACME challenges
- Check initial ACME certs
- Check CA certs after ACME installation
- Run PKI healthcheck in PKI container
- Check external commands
- Verify ACME in PKI container
- Set up client container
- Install certbot in client container
- Register ACME account
- Check ACME accounts after registration
- Enroll client cert
- Check client cert
- Check ACME orders after enrollment
- Check ACME authorizations after enrollment
- Check ACME challenges after enrollment
- Check ACME certs after enrollment
- Check CA certs after enrollment
- Renew client cert
- Check renewed client cert
- Check ACME orders after renewal
- Check ACME authorizations after renewal
- Check ACME challenges after renewal
- Check ACME certs after renewal
- Check CA certs after renewal
- Revoke client cert
- Check CA certs after revocation
- Update ACME account
- Check ACME accounts after update
- Remove ACME account
- Check ACME accounts after unregistration
- Install caddy in client container
- Configure ACME support in caddy
- Start caddy
- Check https is working
- Check ACME accounts after caddy started
- Check CA certs after caddy started
- Remove ACME from PKI container
- Check for warnings
- Check external commands
- Remove CA from PKI container
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check ACME debug log
- Check certbot log

        ## Usage

            tmt run plan --name acme-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
