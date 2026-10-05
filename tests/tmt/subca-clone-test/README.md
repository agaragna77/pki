        # Sub-CA clone

        TMT port of `.github/workflows/subca-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root CA container
- Create root CA in NSS database
- Set up primary DS container
- Set up primary sub-CA container
- Install primary sub-CA (step 1)
- Issue primary sub-CA signing cert
- Install primary sub-CA (step 2)
- Run PKI healthcheck
- Check primary sub-CA admin
- Export primary sub-CA certs
- Set up secondary DS container
- Set up secondary sub-CA container
- Install secondary sub-CA
- Check CS.cfg in primary sub-CA after cloning
- Check CS.cfg in secondary sub-CA
- Run PKI healthcheck
- Check secondary sub-CA admin
- Check users in primary sub-CA and secondary sub-CA
- Check certs in primary sub-CA and secondary sub-CA
- Remove secondary sub-CA
- Remove primary sub-CA
- Check for root CA core dumps
- Check for primary sub-CA core dumps
- Check for secondary sub-CA core dumps

        ## Usage

            tmt run plan --name subca-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
