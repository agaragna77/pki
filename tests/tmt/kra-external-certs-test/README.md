        # KRA with external certs

        TMT port of `.github/workflows/kra-external-certs-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Initialize CA admin in CA container
- Set up KRA DS container
- Set up KRA container
- Install KRA in KRA container (step 1)
- Issue KRA storage cert
- Issue KRA transport cert
- Issue subsystem cert
- Issue SSL server cert
- Issue KRA audit signing cert
- Issue KRA admin cert
- Install KRA in KRA container (step 2)
- Verify KRA admin
- Verify KRA connector in CA
- Remove KRA from KRA container
- Remove CA from CA container
- Check PKI server systemd journal in CA container
- Check CA debug log
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-external-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
