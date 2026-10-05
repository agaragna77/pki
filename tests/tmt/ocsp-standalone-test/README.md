        # Standalone OCSP

        TMT port of `.github/workflows/ocsp-standalone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up client container
- Set up DS container
- Set up CA container
- Install standalone CA
- Import CA certs into client
- Check CA admin
- Check CA users
- Check CA security domain
- Set up OCSP container
- Install standalone OCSP (step 1)
- Issue OCSP signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue OCSP audit signing cert
- Issue OCSP admin cert
- Stop CA
- Install standalone OCSP (step 2)
- Check OCSP server status
- Check OCSP system certs
- Run PKI healthcheck
- Start CA
- Import OCSP certs into client
- Check OCSP admin
- Check OCSP users
- Check OCSP security domain
- Check CRL publishing in CA
- Check cert revocation without CRL publishing
- Add CA subsystem user in OCSP
- Add CRL issuing point in OCSP
- Configure CRL publishing in CA
- Check cert revocation with CRL publishing
- Remove OCSP
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check CA systemd journal
- Check CA access log
- Check CA debug log
- Check OCSP systemd journal
- Check OCSP access log
- Check OCSP debug log

        ## Usage

            tmt run plan --name ocsp-standalone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
