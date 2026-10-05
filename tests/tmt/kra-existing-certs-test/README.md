        # KRA with existing certs

        TMT port of `.github/workflows/kra-existing-certs-test.yml`.

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
- Issue KRA storage cert
- Issue KRA transport cert
- Issue KRA audit signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue KRA admin cert
- Export system certs
- Install KRA with existing certs
- Check KRA storage cert in server's NSS database
- Check KRA transport cert in server's NSS database
- Check KRA audit signing cert in server's NSS database
- Check subsystem cert in server's NSS database
- Check SSL server cert in server's NSS database
- Check KRA admin cert
- Verify KRA connector in CA
- Remove KRA from KRA container
- Remove CA from CA container
- Check PKI server systemd journal in CA container
- Check CA debug log
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-existing-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
