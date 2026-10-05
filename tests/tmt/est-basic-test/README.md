        # Basic EST

        TMT port of `.github/workflows/est-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up Python 3.9
- Install ansible
- Execute est playbook

        ## Usage

            tmt run plan --name est-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
