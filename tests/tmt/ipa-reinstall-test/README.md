        # IPA reinstall

        TMT port of `.github/workflows/ipa-reinstall-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run IPA container
- Install IPA server
- Update PKI server configuration
- Check admin user
- Import CA signing cert
- Check CA agent cert
- Check RA agent cert
- Install KRA
- Check KRA users
- Check IPA CA install log
- Check IPA KRA install log
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log
- Remove IPA server
- Check /etc/pki after removal
- Check /var/lib/pki after removal
- Check /var/log/pki after removal
- Check /root/.dogtag after removal
- Install IPA server again
- Import CA signing cert again
- Check CA agent cert again
- Check RA agent cert again
- Install KRA again
- Check KRA users again
- Check IPA CA install log
- Check IPA KRA install log
- Check CA pkispawn log
- Check KRA pkispawn log
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log
- Remove IPA server again
- Check CA pkidestroy log
- Check KRA pkidestroy log
- Check /etc/pki after removal
- Check /var/lib/pki after removal
- Check /var/log/pki after removal
- Check /root/.dogtag after removal

        ## Usage

            tmt run plan --name ipa-reinstall-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
