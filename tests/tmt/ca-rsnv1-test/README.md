        # CA with RSNv1

        TMT port of `.github/workflows/ca-rsnv1-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check CA certs and keys
- Switch to RSNv3
- Run PKI healthcheck
- Initialize PKI client
- Test CA agent
- Check cert requests in CA
- Check certs in CA
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-rsnv1-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
