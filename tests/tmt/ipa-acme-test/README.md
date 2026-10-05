        # IPA ACME

        TMT port of `.github/workflows/ipa-acme-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Install IPA server in IPA container
- Update PKI server configuration
- Check DS server
- Check admin user
- Install KRA in IPA container
- Check DS server
- Verify CA admin in IPA container
- Enable ACME in IPA container
- Check DS server
- Specify main CA as Authority ID for ACME in IPA container
- Run client container
- Connect client container to network
- Install IPA client in client container
- Verify certbot in client container
- Disable ACME in IPA container
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
- Remove IPA server from IPA container
- Check CA pkidestroy log

        ## Usage

            tmt run plan --name ipa-acme-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
