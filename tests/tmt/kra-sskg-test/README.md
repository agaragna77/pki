        # KRA with SSKG

        TMT port of `.github/workflows/kra-sskg-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install KRA
- Check KRA connector in CA
- Update KRA connector in CA
- Install admin cert
- Create request template for caServerKeygen_UserCert
- Submit request with good password
- Find generated key
- Retrieve generated key
- Import retrieved key
- Submit request with short password
- Submit request with numeric password
- Disable PKCS #12 password constraint
- Submit request with minimal password
- Find generated key
- Retrieve generated key
- Import generated key
- Remove KRA
- Remove CA
- Check for PKI core dumps
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-sskg-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
