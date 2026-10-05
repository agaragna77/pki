        # CA container with existing config

        TMT port of `.github/workflows/ca-container-existing-config-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Install CA
- Set up client container
- Check CA info
- Check CA admin user
- Stop CA
- Export certs
- Export config files
- Export log files
- Set up CA container
- Get Tomcat flavor
- Check conf dir
- Check conf/ca dir
- Check logs dir
- Check logs dir
- Check CA admin user again
- Check cert enrollment
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check CA container logs
- Check CA container debug logs

        ## Usage

            tmt run plan --name ca-container-existing-config-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
