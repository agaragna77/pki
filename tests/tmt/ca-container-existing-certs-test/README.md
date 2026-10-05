        # CA container with existing certs

        TMT port of `.github/workflows/ca-container-existing-certs-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Get Fedora version
- Create CA signing cert
- Create OCSP signing cert
- Create subsystem cert
- Create SSL server cert
- Prepare CA certs and keys
- Set up CA container
- Get Tomcat flavor
- Check conf dir
- Check conf/ca dir
- Check logs dir
- Check logs dir
- Check CA info
- Set up DS container
- Initialize CA database
- Import CA signing cert into CA database
- Import CA OCSP signing cert into CA database
- Import subsystem cert into CA database
- Import SSL server cert into CA database
- Create admin cert
- Check certs in CA
- Add CA admin user
- Add CA admin user into CA groups
- Check CA admin user
- Check cert enrollment
- Restart CA
- Check CA admin user again
- Check DS server systemd journal
- Check DS container logs
- Check CA container logs
- Check CA debug logs

        ## Usage

            tmt run plan --name ca-container-existing-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
