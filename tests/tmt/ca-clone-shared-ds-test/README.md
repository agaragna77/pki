        # CA clone with shared DS

        TMT port of `.github/workflows/ca-clone-shared-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up primary PKI container
- Install primary CA
- Export certs and keys from primary CA
- Set up secondary PKI container
- Install secondary CA
- Check system certs in primary CA and secondary CA
- Check CS.cfg in primary CA after cloning
- Check CS.cfg in secondary CA
- Check users in primary CA and secondary CA
- Check certs in primary CA and secondary CA
- Check security domain in primary CA and secondary CA
- Remove secondary CA
- Remove primary CA

        ## Usage

            tmt run plan --name ca-clone-shared-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
