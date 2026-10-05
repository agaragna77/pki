        # PKI NSS CLI with AES

        TMT port of `.github/workflows/pki-nss-aes-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Create AES key
- Verify key type

        ## Usage

            tmt run plan --name pki-nss-aes-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
