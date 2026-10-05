        # CA with request notification

        TMT port of `.github/workflows/ca-notification-request-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install mail server and client
- Start mail server
- Install CA
- Configure request notification
- Restart CA subsystem
- Check CA admin
- Check messages before enrollment request
- Submit enrollment request
- Check messages after enrollment request
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-notification-request-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
