        # IPA KRA

        TMT port of `.github/workflows/ipa-kra-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Install IPA server
- Update PKI server configuration
- Check DS server
- Check IPA admin user
- Install CA admin cert
- Install RA agent cert
- Install KRA
- Check PKI certs and keys
- Check DS server after installing KRA
- Check CA admin cert after installing KRA
- Check KRA users
- Check RA agent cert
- Check webapps
- Check subsystems
- Run PKI healthcheck
- Configure test environment
- Run test_vault_plugin.py
- Create vault
- Retrieve initial vault content
- Generate private key
- Archive private key
- Retrieve private key
- Check IPA CA install log
- Check IPA KRA install log
- Check HTTPD access logs
- Check HTTPD error logs
- Check DS server systemd journal
- Check DS access logs
- Check DS error logs
- Check DS security logs
- Check CA pkispawn log
- Check KRA pkispawn log
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log
- Remove IPA server
- Check CA pkidestroy log
- Check KRA pkidestroy log

        ## Usage

            tmt run plan --name ipa-kra-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
