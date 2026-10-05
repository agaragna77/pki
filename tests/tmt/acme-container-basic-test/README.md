        # Basic ACME container

        TMT port of `.github/workflows/acme-container-basic-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up client container
- Install dependencies in client container
- Create shared folders
- Set up ACME container
- Get Fedora version
- Get Tomcat flavor
- Check conf dir
- Check conf/acme dir
- Check logs dir
- Check logs dir
- Install CA signing cert
- Check ACME status
- Register ACME account
- Enroll client cert
- Check client cert
- Renew client cert
- Update ACME account
- Remove ACME account
- Restart ACME
- Check ACME status again
- Check ACME container logs
- Check certbot logs
- Check client container logs

        ## Usage

            tmt run plan --name acme-container-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
