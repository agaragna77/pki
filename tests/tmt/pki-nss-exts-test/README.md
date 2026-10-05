        # PKI NSS CLI with Extensions

        TMT port of `.github/workflows/pki-nss-exts-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Create CA signing cert request
- Issue self-signed CA signing cert
- Import CA signing cert
- Create subordinate CA signing cert request
- Issue subordinate CA signing cert
- Create SSL server cert request
- Issue SSL server cert

        ## Usage

            tmt run plan --name pki-nss-exts-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
