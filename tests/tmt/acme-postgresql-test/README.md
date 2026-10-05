        # ACME with postgresql back-end

        TMT port of `.github/workflows/acme-postgresql-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up DS container
- Set up PKI container
- Install CA in PKI container
- Install CA admin cert
- Check initial CA certs
- Create postgresql certificates
- Create postgresql Docker file
- Build postgrsql image with certificates
- Deploy postgresql
- Set up database drivers
- Install ACME in PKI container
- Check ACME database config
- Check ACME issuer config
- Check ACME realm config
- Run PKI healthcheck in PKI container
- Verify ACME in PKI container
- Check initial ACME accounts
- Check initial ACME orders
- Check initial ACME authorizations
- Check initial ACME challenges
- Check initial ACME certs
- Check CA certs after ACME installation
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
- Remove ACME from PKI container
- Remove CA from PKI container
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check ACME debug log
- Check certbot log

        ## Usage

            tmt run plan --name acme-postgresql-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
