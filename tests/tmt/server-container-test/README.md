        # Server container

        TMT port of `.github/workflows/server-container-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Set up server container
- Get Fedora version
- Get Tomcat flavor
- Check conf dir
- Check logs dir
- Check logs dir
- Check server info
- Restart server
- Check server info again
- Check client container logs
- Check server container logs

        ## Usage

            tmt run plan --name server-container-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
