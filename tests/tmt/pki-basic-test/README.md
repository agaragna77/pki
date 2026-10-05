        # Basic PKI CLI

        TMT port of `.github/workflows/pki-basic-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki CLI help message
- Check pki CLI version
- Check pki CLI with wrong option
- Check pki CLI with wrong sub-command
- Check pki CLI in shell mode (with prompts)
- Check pki CLI in batch mode (without prompts)

        ## Usage

            tmt run plan --name pki-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
