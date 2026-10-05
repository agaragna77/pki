        # CA with existing DS

        TMT port of `.github/workflows/ca-existing-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up PKI container
- Create PKI server
- Create CA signing cert in server's NSS database
- Create CA OCSP signing cert in server's NSS database
- Create CA audit signing cert in server's NSS database
- Create subsystem cert in server's NSS database
- Create SSL server cert in server's NSS database
- Create CA admin cert in client's NSS database
- Check pki-server ca CLI help message
- Check pki-server ca-create CLI help message
- Create CA subsystem
- Set up DS container
- Configure connection to CA database
- Check connection to CA database
- Initialize CA database
- Add CA search indexes
- Rebuild CA search indexes
- Import CA signing cert into CA database
- Import CA OCSP signing cert into CA database
- Import CA audit signing cert into CA database
- Import subsystem cert into CA database
- Import SSL server cert into CA database
- Import admin cert into CA database
- Create security domain database
- Configure security domain manager
- Add subsystem user
- Assign roles to subsystem user
- Add CA admin user
- Assign roles to CA admin user
- Install CA
- Run PKI healthcheck
- Check CA admin user
- Check CA security domain
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-existing-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
