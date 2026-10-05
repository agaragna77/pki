        # ACME container with CA

        TMT port of `.github/workflows/acme-container-ca-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up client container
- Install dependencies in client container
- Set up CA DS container
- Create CA shared folders
- Create CA signing cert
- Create SSL server cert for CA
- Create OCSP signing cert for CA
- Export CA certs and keys
- Set up CA container
- Check CA info
- Initialize CA database
- Create admin cert
- Add CA admin user
- Check CA admin user
- Set up ACME DS container
- Create ACME shared folders
- Create SSL server cert for ACME
- Export ACME certs and keys
- Configure ACME database
- Configure ACME issuer
- Configure ACME realm
- Set up ACME container
- Check ACME status
- Initialize ACME database
- Initialize ACME realm
- Register ACME account
- Enroll client cert
- Check client cert
- Renew client cert
- Revoke client cert
- Update ACME account
- Remove ACME account
- Check CA DS container logs
- Check CA container logs
- Check ACME DS container logs
- Check ACME container logs
- Check client container logs
- Check certbot logs

        ## Usage

            tmt run plan --name acme-container-ca-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
