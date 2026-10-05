        # ACME with existing NSS database

        TMT port of `.github/workflows/acme-existing-nssdb-test.yml`.

        ## Steps

        - Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up CA DS container
- Set up CA container
- Get Fedora version
- Get Tomcat flavor
- Install CA
- Install CA admin cert
- Check initial CA certs
- Set up ACME DS container
- Set up ACME container
- Create PKI server for ACME
- Import CA signing cert for ACME
- Issue SSL server cert for ACME
- Install ACME
- Check ACME server base dir after installation
- Check ACME server conf dir after installation
- Check ACME server logs dir after installation
- Check ACME server logs dir after installation
- Check ACME base dir
- Check ACME conf dir
- Check ACME database config
- Check ACME issuer config
- Check ACME realm config
- Check ACME logs dir
- Check ACME system certs
- Initialize ACME database
- Initialize ACME realm
- Check initial ACME accounts
- Check initial ACME orders
- Check initial ACME authorizations
- Check initial ACME challenges
- Check initial ACME certs
- Check CA certs after ACME installation
- Run PKI healthcheck in ACME container
- Verify ACME in ACME container
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
- Remove ACME
- Remove CA
- Check ACME server base dir after removal
- Check ACME server conf dir after removal
- Check ACME server logs dir after removal
- Check ACME server logs dir after removal
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA server systemd journal
- Check CA debug log
- Check ACME DS server systemd journal
- Check ACME DS container logs
- Check ACME server systemd journal
- Check ACME debug log
- Check certbot log

        ## Usage

            tmt run plan --name acme-existing-nssdb-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
