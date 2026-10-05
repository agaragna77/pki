        # PKI PKCS12 CLI

        TMT port of `.github/workflows/pki-pkcs12-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki pkcs12 CLI help message
- Create CA signing cert
- Create SSL server cert
- Create audit signing cert
- Check certs and keys in NSS database
- Export everything into PKCS #12 file
- Check certs and keys in PKCS #12 file
- Remove CA signing key from PKCS #12 file
- Remove audit signing cert and key from PKCS #12 file
- Re-import audit signing cert and key into PKCS #12 file
- Import everything from PKCS #12 file
- Import PKCS #12 file without trust flags
- Import PKCS #12 file without CA certs
- Import PKCS #12 file without user certs

        ## Usage

            tmt run plan --name pki-pkcs12-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
