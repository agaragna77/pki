        # CA connection with DS

        TMT port of `.github/workflows/ca-ds-connection-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check DS backends
- Initialize PKI client
- Create cert request
- Test request enrollment
- Stop the DS
- Restart the DS
- Start without the DS
- Start the DS with running CA
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-ds-connection-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
