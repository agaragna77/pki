        # TKS with HSM

        TMT port of `.github/workflows/tks-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install dependencies
- Create SoftHSM token
- Install CA with HSM
- Check system certs in internal token
- Check system certs in HSM
- Install TKS with HSM
- Check system certs in internal token
- Check tks_audit_signing cert in internal token
- Check system certs in HSM
- Check tks_audit_signing cert in HSM
- Run PKI healthcheck
- Check TKS admin
- Remove TKS
- Remove CA
- Remove SoftHSM token
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check TKS debug log

        ## Usage

            tmt run plan --name tks-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
