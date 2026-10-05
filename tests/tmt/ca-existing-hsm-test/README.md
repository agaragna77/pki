        # CA with existing HSM

        TMT port of `.github/workflows/ca-existing-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install dependencies
- Create SoftHSM token
- Create PKI server
- Create CA signing cert
- Create CA OCSP signing cert
- Create CA audit signing cert
- Create subsystem cert
- Create SSL server cert
- Create admin cert
- Check SoftHSM files
- Install CA with existing HSM
- Run PKI healthcheck
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Check CA certs and requests
- Remove CA
- Remove SoftHSM token
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-existing-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
