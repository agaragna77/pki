        # KRA with CMC

        TMT port of `.github/workflows/kra-cmc-test.yml`.

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
- Issue KRA storage cert with CMC
- Issue KRA transport cert with CMC
- Issue subsystem cert with CMC
- Issue SSL server cert with CMC
- Issue KRA audit signing cert with CMC
- Issue KRA admin cert with CMC
- Install KRA in KRA container (step 2)
- Verify KRA admin
- Remove KRA from KRA container
- Remove CA from CA container
- Check PKI server systemd journal in CA container
- Check CA debug log
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-cmc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
