        # OCSP with CMC

        TMT port of `.github/workflows/ocsp-cmc-test.yml`.

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
- Issue OCSP signing cert with CMC
- Issue subsystem cert with CMC
- Issue SSL server cert with CMC
- Issue OCSP audit signing cert with CMC
- Issue OCSP admin cert with CMC
- Install OCSP in OCSP container (step 2)
- Run PKI healthcheck
- Verify OCSP admin
- Remove OCSP from OCSP container
- Remove CA from CA container
- Check CA DS server systemd journal
- Check CA DS container logs
- Check for CA core dumps
- Check CA systemd journal
- Check CA debug log
- Check OCSP DS server systemd journal
- Check OCSP DS container logs
- Check for OCSP core dumps
- Check OCSP systemd journal
- Check OCSP debug log

        ## Usage

            tmt run plan --name ocsp-cmc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
