        # TPS with HSM

        TMT port of `.github/workflows/tps-hsm-test.yml`.

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
- Install KRA with HSM
- Check system certs in internal token
- Check system certs in HSM
- Install TKS
- Check system certs in internal token
- Check system certs in HSM
- Install TPS
- Check system certs in internal token
- Check tps_audit_signing cert in internal token
- Check system certs in HSM
- Check tps_audit_signing cert in HSM
- Run PKI healthcheck
- Check TPS admin
- Remove TPS
- Remove TKS
- Remove KRA
- Remove CA
- Remove SoftHSM token
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log
- Check TKS debug log
- Check TPS debug log

        ## Usage

            tmt run plan --name tps-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
