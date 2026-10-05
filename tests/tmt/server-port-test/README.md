        # Server port

        TMT port of `.github/workflows/server-port-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check server.xml
- Run PKI healthcheck
- Initialize PKI client
- Check CA admin
- Remove CA
- Install CA again
- Check CA admin again
- Remove CA again
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name server-port-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
