        # CA Python API

        TMT port of `.github/workflows/python-ca-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Update PKI server configuration
- Set up client
- Check PKI server info
- Check PKI server info with REST API v1
- Find CA cert request templates
- Show CA cert request template
- Find CA cert request templates with REST API v1
- Show CA cert request template with REST API v1
- Check CA cert requests
- Check CA cert requests with REST API v1
- Check CA certs
- Check CA certs with REST API v1
- Check CA users
- Check CA users with REST API v1
- Check API v1 are deprecated
- Make the API v1 disabled
- Check API v1 are disabled
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name python-ca-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
