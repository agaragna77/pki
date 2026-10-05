        # KRA with SoftHSM

        TMT port of `.github/workflows/kra-softhsm-test.yml`.

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
- Check kra_storage cert in internal token
- Check kra_transport cert in internal token
- Check kra_audit_signing cert in internal token
- Check system certs in HSM
- Check kra_storage cert in HSM
- Check kra_transport cert in HSM
- Check kra_audit_signing cert in HSM
- Run PKI healthcheck
- Check admin cert
- Remove KRA
- Remove CA
- Remove SoftHSM token
- Check for PKI core dumps
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-softhsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
