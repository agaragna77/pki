        # CA with existing config

        TMT port of `.github/workflows/ca-existing-config-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Install CA
- Check instance
- Check system certs
- Check CA admin
- Remove CA
- Check instance
- Check PKI server base dir after first removal
- Check PKI server conf dir after first removal
- Check PKI server logs dir after first removal
- Check PKI server logs dir after first removal
- Check admin cert after first removal
- Install CA with the same config
- Check instance
- Check PKI server config after second installation
- Check CA config after second installation
- Check system certs again
- Check CA admin again
- Check CA debug log
- Remove CA again
- Check instance
- Check PKI server base dir after second removal
- Check PKI server conf dir after second removal
- Check PKI server logs dir after second removal
- Check admin cert after second removal
- Install CA with new config and old admin cert
- Remove old admin cert
- Install CA with new config and no admin cert
- Check system certs again
- Check CA admin
- Remove CA again
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal

        ## Usage

            tmt run plan --name ca-existing-config-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
