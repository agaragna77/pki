        # PKI Password CLI

        TMT port of `.github/workflows/pki-password-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki password CLI help message
- Generate password with default characters
- Generate password with user-provided characters

        ## Usage

            tmt run plan --name pki-password-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
