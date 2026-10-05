        # KRA with RSA-OAEP

        TMT port of `.github/workflows/kra-rsa-oaep-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check keywrap config in CA
- Install KRA
- Check keywrap config in KRA
- Check transport unit config in KRA
- Check storage unit config in KRA
- Check KRA transport cert
- Check KRA connector config in CA
- Check CA info
- Check KRA info
- Run PKI healthcheck
- Check KRA admin
- Generate CSR
- Enroll cert with key archival
- Import cert
- Check archived key
- Recover key
- Check recovered key
- Remove KRA
- Remove CA
- Check for PKI core dumps
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-rsa-oaep-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
