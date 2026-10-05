        # CA with RSA

        TMT port of `.github/workflows/ca-rsa-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check system certs keys
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Run PKI healthcheck
- Check authenticating as CA admin user
- Check CA admin cert
- Check issuing SSL server cert
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-rsa-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
