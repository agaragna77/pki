        # IPA renewal

        TMT port of `.github/workflows/ipa-renewal-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Configure short-lived SSL server cert profile
- Configure short-lived subsystem cert profile
- Configure short-lived audit signing cert profile
- Configure short-lived OCSP signing cert profile
- Configure short-lived admin cert profile
- Install IPA server with CA
- Update PKI server configuration
- Check admin user
- Check HTTPD certs
- Check DS certs
- Check PKI system certs
- Check CA database config
- Check CA admin cert
- Check RA agent cert
- Run PKI healthcheck
- Renew certs using ipa-cert-fix
- Check HTTPD certs after renewal
- Check DS certs after renewal
- Check CA database config after renewal
- Check PKI system certs after renewal
- Check CA admin cert after renewal
- Check RA agent cert after renewal
- Run PKI healthcheck after renewal
- Check IPA CA install log
- Check HTTPD access logs
- Check HTTPD error logs
- Check DS server systemd journal
- Check DS access logs
- Check DS error logs
- Check DS security logs
- Check CA pkispawn log
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Remove IPA server
- Check CA pkidestroy log

        ## Usage

            tmt run plan --name ipa-renewal-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
