        # HTTPS connector with NSS database

        TMT port of `.github/workflows/server-https-nss-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up server container
- Create PKI server
- Check pki-server nss CLI help message
- Check pki-server nss-create CLI help message
- Create NSS database in PKI server
- Create CA signing cert
- Create SSL server cert
- Create HTTPS connector with NSS database
- Deploy webapps
- Start PKI server
- Set up client container
- Wait for PKI server to start
- Check PKI CLI with unknown issuer
- Check PKI CLI with unknown issuer with wrong hostname
- Check PKI CLI with newly trusted server cert
- Check PKI CLI with trusted server cert with wrong hostname
- Check PKI CLI with already trusted server cert
- Check PKI CLI with expired server cert
- Stop PKI server
- Remove PKI server
- Check PKI server systemd journal

        ## Usage

            tmt run plan --name server-https-nss-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
