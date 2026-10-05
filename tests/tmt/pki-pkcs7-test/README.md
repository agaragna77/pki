        # PKI PKCS7 CLI

        TMT port of `.github/workflows/pki-pkcs7-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki pkcs7 CLI help message
- Generate CA signing cert request
- Issue self-signed CA signing cert
- Import CA signing cert
- Generate SSL server cert request
- Issue SSL server cert signed by CA signing cert
- Import SSL server cert
- Export SSL server cert chain into PKCS #7 chain
- Convert cert chain into separate PEM certificates
- Merge PEM certificates into a PKCS #7 chain
- Remove certs from NSS database
- Import PKCS #7 chain into NSS database
- Verify CA signing cert trust flags
- Verify SSL server cert trust flags
- Convert PKCS #7 chain into a series of PEM certificates
- Remove certs from NSS database
- Import PEM certificates into NSS database
- Verify CA signing cert trust flags
- Verify SSL server cert trust flags

        ## Usage

            tmt run plan --name pki-pkcs7-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
