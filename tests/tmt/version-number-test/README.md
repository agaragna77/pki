        # Version number

        TMT port of `.github/workflows/version-number-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Get version number from RPM spec
- Check version numbers in pom.xml
- Setup git
- Update to version with a phase
- Update to version without a phase
- Update to version with a phase again

        ## Usage

            tmt run plan --name version-number-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
