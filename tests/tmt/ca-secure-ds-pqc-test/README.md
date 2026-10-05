        # CA with secure DS (PQC)

        TMT port of `.github/workflows/ca-secure-ds-pqc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Enable ML-DSA in default crypto-policies
- Create DS signing cert
- Create DS server cert
- Import certs into DS container
- Install CA
- Run PKI healthcheck
- Verify DS connection
- Check DS signing cert
- Check DS server cert
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-secure-ds-pqc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
