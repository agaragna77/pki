        # Sub-CA with external cert

        TMT port of `.github/workflows/subca-external-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create root CA in NSS database
- Install subordinate CA (step 1)
- Issue subordinate CA signing cert
- Install subordinate CA (step 2)
- Run PKI healthcheck
- Verify CA admin
- Check cert requests in CA
- Remove subordinate CA

        ## Usage

            tmt run plan --name subca-external-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
