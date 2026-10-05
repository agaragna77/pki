        # Python lint

        TMT port of `.github/workflows/python-lint-test.yml`.

        ## Steps

        - Clone repository
- Retrieve runner image
- Load runner image
- Run container
- Run Python lint
- Run Python flake8

        ## Usage

            tmt run plan --name python-lint-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
