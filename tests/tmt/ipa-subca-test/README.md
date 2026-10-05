        # IPA with Sub-CA

        TMT port of `.github/workflows/ipa-subca-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Create root CA
- Generate IPA cert request
- Issue IPA cert
- Install IPA server with Sub-CA
- Update PKI server configuration
- Check admin user
- Check lightweight CAs
- Create lightweight CAs
- Generate certificate in the CAs
- Remove lightweight CAs
- Check HTTPD access logs
- Check HTTPD error logs
- Check DS server systemd journal
- Check DS access logs
- Check DS error logs
- Check DS security logs
- Check IPA CA install log
- Check CA pkispawn log
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Remove IPA server
- Check CA pkidestroy log

        ## Usage

            tmt run plan --name ipa-subca-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
