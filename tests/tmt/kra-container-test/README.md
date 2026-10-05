        # KRA container

        TMT port of `.github/workflows/kra-container-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Install ASN.1 parser
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
- Create KRA storage cert
- Create KRA transport cert
- Create KRA subsystem cert
- Create KRA SSL server cert
- Prepare KRA certs and keys
- Set up KRA container
- Wait for KRA container to start
- Get Fedora version
- Get Tomcat flavor
- Check KRA conf dir
- Check KRA conf/kra dir
- Check KRA logs dir
- Check KRA logs dir
- Check KRA info
- Set up KRA DS container
- Set up KRA database
- Add KRA admin user
- Add KRA admin user into KRA groups
- Check KRA admin user
- Add CA subsystem user in KRA
- Assign roles to CA subsystem user
- Configure KRA connector in CA
- Restart CA
- Request cert with key archival
- Issue cert with key archival
- Check archived key
- Check key retrieval
- Restart KRA
- Check KRA admin user again
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA container logs
- Check CA debug logs
- Check KRA DS server systemd journal
- Check KRA DS container logs
- Check KRA container logs
- Check KRA debug logs
- Check client container logs

        ## Usage

            tmt run plan --name kra-container-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
