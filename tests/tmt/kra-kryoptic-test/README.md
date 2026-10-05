        # KRA with Kryoptic

        TMT port of `.github/workflows/kra-kryoptic-test.yml`.

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
- Check system certs in internal token
- Check system certs in HSM
- Install KRA with HSM
- Check for warnings
- Check external commands
- Check system certs in internal token
- Check system certs in HSM
- Check kra_storage cert in HSM
- Check kra_transport cert in HSM
- Check kra_audit_signing cert in HSM
- Run PKI healthcheck
- Check admin cert
- Remove KRA
- Check for warnings
- Check external commands
- Remove CA
- Remove Kryoptic token
- Check for PKI core dumps
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-kryoptic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
