        # CA API

        TMT port of `.github/workflows/ca-api-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Disable access log buffer
- Configure RESTEasy logging
- Restart PKI server
- Install CA signing cert
- Install CA admin cert
- Check pki info with default API
- Check pki info with API v1
- Check pki ca-cert-find with default API
- Check pki ca-cert-find with API v1
- Check pki ca-user-show with default API
- Check pki ca-user-show with API v1
- Check pki ca-cert-request-find with default API
- Check pki ca-cert-request-find with API v1
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name ca-api-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
