        # CA renewal using pki ca-cert-issue

        TMT port of `.github/workflows/ca-renewal-manual-test.yml`.

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
- Configure short-lived admin cert profile
- Install CA
- Check system cert keys
- Run PKI healthcheck
- Check CA admin
- Restart PKI server with expired certs
- Run PKI healthcheck
- Check CA admin
- Create temp SSL server cert
- Restart PKI server with temp SSL server cert
- Run PKI healthcheck
- Check PKI client
- Renew SSL server cert using pki ca-cert-issue
- Renew subsystem cert using pki ca-cert-issue
- Update subsystem user cert
- Renew audit signing cert using pki ca-cert-issue
- Renew OCSP signing cert using pki ca-cert-issue
- Renew admin cert using pki ca-cert-issue
- Update admin user cert
- Restart PKI server with renewed certs
- Check cert keys after renewal
- Run PKI healthcheck
- Check CA admin
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check CA selftests log

        ## Usage

            tmt run plan --name ca-renewal-manual-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
