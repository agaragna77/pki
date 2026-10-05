        # TKS with existing config

        TMT port of `.github/workflows/tks-existing-config-test.yml`.

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
- Install TKS
- Check system certs
- Check TKS admin
- Remove TKS
- Check PKI server base dir after first removal
- Check PKI server conf dir after first removal
- Check PKI server logs dir after first removal
- Check PKI server logs dir after first removal
- Install TKS again
- Check PKI server config after second installation
- Check TKS config after second installation
- Check system certs again
- Check TKS admin again
- Check CA debug log
- Check TKS debug log
- Remove TKS again
- Remove CA
- Check PKI server base dir after second removal
- Check PKI server conf dir after second removal
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal

        ## Usage

            tmt run plan --name tks-existing-config-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
