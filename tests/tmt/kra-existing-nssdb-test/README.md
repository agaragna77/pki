        # KRA with existing NSS database

        TMT port of `.github/workflows/kra-existing-nssdb-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up CA container
- Install CA
- Install CA admin cert
- Set up KRA container
- Create PKI server
- Issue KRA storage cert
- Issue KRA transport cert
- Issue KRA audit signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue KRA admin cert
- Install KRA with existing NSS database
- Check KRA storage cert
- Check KRA transport cert
- Check KRA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check KRA admin cert
- Verify KRA connector in CA
- Remove KRA from KRA container
- Remove CA from CA container
- Check PKI server systemd journal in CA container
- Check CA debug log
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-existing-nssdb-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
