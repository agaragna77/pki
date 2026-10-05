        # CA with Kryoptic

        TMT port of `.github/workflows/ca-kryoptic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Configure crypto-policies
- Install Kryoptic
- Create Kryoptic token
- Install CA with HSM
- Check for warnings
- Check external commands
- Check system certs in internal token
- Check system certs in HSM
- Check ca_signing cert in HSM
- Check ca_ocsp_signing cert in HSM
- Check ca_audit_signing cert in HSM
- Check subsystem cert in HSM
- Check sslserver cert in HSM
- Run PKI healthcheck
- Check admin cert
- Remove CA
- Check for warnings
- Check external commands
- Remove Kryoptic token
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-kryoptic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
