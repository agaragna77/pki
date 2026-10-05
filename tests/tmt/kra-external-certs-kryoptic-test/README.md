        # KRA with external certs on Kryoptic

        TMT port of `.github/workflows/kra-external-certs-kryoptic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up CA container
- Install Kryoptic
- Create CA Kryoptic token
- Create root CA
- Install sub CA (step 1)
- Issue sub CA signing cert
- Install sub CA (step 2)
- Check CA admin
- Set up KRA container
- Install Kryoptic
- Create KRA Kryoptic token
- Install KRA (step 1)
- Issue KRA storage cert
- Issue KRA transport cert
- Issue subsystem cert
- Issue SSL server cert
- Issue KRA audit signing cert
- Issue KRA admin cert
- Install KRA (step 2)
- Check KRA admin
- Remove KRA
- Remove KRA Kryoptic token
- Remove sub CA
- Remove root CA
- Remove CA Kryoptic token
- Check DS server systemd journal
- Check sub CA server systemd journal
- Check sub CA debug log
- Check KRA server systemd journal
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-external-certs-kryoptic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
