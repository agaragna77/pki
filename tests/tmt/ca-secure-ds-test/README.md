        # CA with secure DS

        TMT port of `.github/workflows/ca-secure-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create DS signing cert
- Create DS server cert
- Import certs into DS container
- Install CA
- Run PKI healthcheck
- Verify DS connection
- Verify CA admin
- Check cert requests in CA
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-secure-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
