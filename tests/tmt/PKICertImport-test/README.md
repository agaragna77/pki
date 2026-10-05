        # PKICertImport

        TMT port of `.github/workflows/PKICertImport-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Run PKICertImport test

        ## Usage

            tmt run plan --name PKICertImport-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
