        # KRA Python API

        TMT port of `.github/workflows/python-kra-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install KRA
- Update PKI server configuration
- Set up client
- Check PKI server info
- Check PKI server info with REST API v1
- Check KRA users
- Check KRA users with REST API v1
- Enroll cert with key archival
- Check key requests
- Check key requests with REST API v1
- Check archived keys
- Check archived keys with REST API v1
- Change key status
- Change key status with REST API v1
- Archive secret
- Retrieve secret
- Archive secret with REST API v1
- Retrieve secret with REST API v1
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name python-kra-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
