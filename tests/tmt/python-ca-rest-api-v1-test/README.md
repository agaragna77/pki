        # CA Python API with REST API v1

        TMT port of `.github/workflows/python-ca-rest-api-v1-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up client container
- Create CA signing cert
- Create OCSP signing cert
- Create audit signing cert
- Create subsystem cert
- Create SSL server cert
- Create admin cert
- Export system certs and keys to PKCS #12 file
- Export admin cert and key to PKCS #12 file
- Export admin key to PEM file
- Set up DS container
- Configure DS database
- Add PKI schema
- Add CA base entry
- Add CA database entries
- Add CA search indexes
- Rebuild CA search indexes
- Add CA ACL resources
- Add admin user
- Assign admin cert to admin user
- Add admin user into CA groups
- Create PKI CA 11.4 Dockerfile
- Build PKI CA 11.4 image
- Create PKI CA 11.4 container
- Wait for CA container to start
- Check PKI server info
- Find CA cert request templates
- Show CA cert request template
- Check CA cert requests
- Check CA certs
- Check CA users
- Check DS server systemd journal
- Check DS container logs
- Check PKI server access log
- Check CA container logs

        ## Usage

            tmt run plan --name python-ca-rest-api-v1-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
