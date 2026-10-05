        # Java Client

        TMT port of `.github/workflows/java-client-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install CA admin cert
- Install JDK
- Check CACertClientExample
- Check CAAccountClientExample
- Remove CA
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name java-client-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
