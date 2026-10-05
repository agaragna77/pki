        # CA automated renewal

        TMT port of `.github/workflows/ca-renewal-automated-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Configure short-lived SSL server cert profile
- Configure short-lived subsystem cert profile
- Configure short-lived audit signing cert profile
- Configure short-lived OCSP signing cert profile
- Install CA
- Check CA database config
- Check system cert keys
- Check system certs
- Run PKI healthcheck
- Check CA admin
- Check CA subsystem user
- Restart PKI server with expired certs
- Run PKI healthcheck
- Check PKI client
- Check CA admin
- Renew system certs using pki-server cert-fix
- Check CA database config after renewal
- Check system certs after renewal
- Check cert keys after renewal
- Run PKI healthcheck
- Check CA admin
- Update CA subsystem user cert
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check CA selftests log

        ## Usage

            tmt run plan --name ca-renewal-automated-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
