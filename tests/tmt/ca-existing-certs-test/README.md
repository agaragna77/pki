        # CA with existing certs

        TMT port of `.github/workflows/ca-existing-certs-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create CA signing cert
- Create CA OCSP signing cert
- Create CA audit signing cert
- Create subsystem cert
- Create SSL server cert
- Export system certs
- Create self-signed admin cert
- Install CA with existing system certs and self-signed admin cert
- Create CA-signed admin cert
- Install CA with existing system certs and CA-signed admin cert
- Run PKI healthcheck
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Check CA certs and requests
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-existing-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
