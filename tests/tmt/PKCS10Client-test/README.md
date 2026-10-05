        # PKCS10Client

        TMT port of `.github/workflows/PKCS10Client-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Install ASN.1 parser
- Create CA signing cert with RSA key
- Create SSL server cert request with RSA key
- Issue SSL server cert
- Import SSL server cert
- Verify trust flags
- Verify key type
- Delete SSL server cert and key
- Create CA signing cert with EC key
- Create SSL server cert request with EC key
- Issue SSL server cert
- Import SSL server cert
- Verify trust flags
- Verify key type
- Delete SSL server cert and key

        ## Usage

            tmt run plan --name PKCS10Client-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
