        # Basic IPA

        TMT port of `.github/workflows/ipa-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Install IPA server
- Update PKI server configuration
- Check admin user
- Check webapps
- Check subsystems
- Check DS certs and keys
- Check PKI certs and keys
- Check CA database config
- Check DS server
- Check CA users
- Check CA subsystem user
- Check CA admin user
- Check PKI database user
- Check IPA RA user
- Check ACME subsystem user
- Check CA admin cert
- Check RA agent cert
- Check HTTPD certs
- Run PKI healthcheck
- Check external commands
- Configure test environment
- Run test_caacl_plugin.py
- Run test_caacl_profile_enforcement.py
- Run test_cert_plugin.py
- Run test_certprofile_plugin.py
- Run test_ca_plugin.py
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

            tmt run plan --name ipa-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
