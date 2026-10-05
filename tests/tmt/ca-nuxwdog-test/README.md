        # CA with Nuxwdog

        TMT port of `.github/workflows/ca-nuxwdog-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check CA
- Stop CA
- Enable Nuxwdog
- Start CA with Nuxwdog
- Check systemd journal
- Check CA again
- Stop CA with Nuxwdog
- Disable Nuxwdog
- Start CA
- Check CA again
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-nuxwdog-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
