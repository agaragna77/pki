        # Server user

        TMT port of `.github/workflows/server-user-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Tomcat flavor
- Create custom user and group
- Install CA with custom user and group
- Check PKI server process
- Run PKI healthcheck
- Initialize PKI client
- Check CA admin
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name server-user-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
