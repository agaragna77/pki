        # OCSP on separate instance

        TMT port of `.github/workflows/ocsp-separate-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Check security domain config in CA
- Install banner in CA container
- Set up OCSP DS container
- Set up OCSP container
- Install OCSP in OCSP container
- Check for warnings
- Check external commands
- Check OCSP certs
- Check security domain config in OCSP
- Install banner in OCSP container
- Run PKI healthcheck
- Verify OCSP admin
- Remove OCSP from OCSP container
- Check for warnings
- Check external commands
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

            tmt run plan --name ocsp-separate-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
