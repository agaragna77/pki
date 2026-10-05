        # PKI PKCS11 CLI

        TMT port of `.github/workflows/pki-pkcs11-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki pkcs11 CLI help message
- Create HSM token
- Create cert in internal token
- Create cert in HSM
- Verify certs creation
- Verify cert keys creation
- Remove certs
- Remove cert keys
- Verify certs removal
- Verify cert keys removal
- Remove HSM token

        ## Usage

            tmt run plan --name pki-pkcs11-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
