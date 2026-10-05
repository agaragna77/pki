        # OCSP with external certs

        TMT port of `.github/workflows/ocsp-external-certs-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Initialize CA admin in CA container
- Set up OCSP DS container
- Set up OCSP container
- Install OCSP in OCSP container (step 1)
- Issue OCSP signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue OCSP audit signing cert
- Issue OCSP admin cert
- Install OCSP in OCSP container (step 2)
- Run PKI healthcheck
- Verify OCSP admin
- Remove OCSP from OCSP container
- Remove CA from CA container
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA systemd journal
- Check CA debug log
- Check OCSP DS server systemd journal
- Check OCSP DS container logs
- Check OCSP systemd journal
- Check OCSP debug log

        ## Usage

            tmt run plan --name ocsp-external-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
