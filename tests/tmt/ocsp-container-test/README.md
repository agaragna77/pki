        # OCSP container

        TMT port of `.github/workflows/ocsp-container-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Set up CA container
- Check CA info
- Set up CA DS container
- Initialize CA database
- Import CA signing cert into CA database
- Import CA OCSP signing cert into CA database
- Import CA subsystem cert into CA database
- Import SSL server cert into CA database
- Create admin cert
- Add CA admin user
- Add CA admin user into CA groups
- Check CA admin user
- Create OCSP signing cert
- Create OCSP subsystem cert
- Create OCSP SSL server cert
- Prepare OCSP certs and keys
- Set up OCSP container
- Wait for OCSP container to start
- Get Fedora version
- Get Tomcat flavor
- Check OCSP conf dir
- Check OCSP conf/ocsp dir
- Check OCSP logs dir
- Check OCSP logs dir
- Check OCSP info
- Set up OCSP DS container
- Set up OCSP database
- Add OCSP admin user
- Add OCSP admin user into OCSP groups
- Check OCSP admin user
- Add CA subsystem user in OCSP
- Assign roles to CA subsystem user
- Add CRL issuing point
- Configure OCSP connector in CA
- Restart CA
- Create user cert
- Check OCSP responder with initial CRL
- Check OCSP responder with after revocation
- Check OCSP responder with after unrevocation
- Restart OCSP
- Check OCSP admin user again
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA container logs
- Check CA debug logs
- Check OCSP DS server systemd journal
- Check OCSP DS container logs
- Check OCSP container logs
- Check OCSP debug logs
- Check client container logs

        ## Usage

            tmt run plan --name ocsp-container-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
