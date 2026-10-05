        # Sub-CA with CMC

        TMT port of `.github/workflows/subca-cmc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root DS container
- Set up root PKI container
- Install root CA in root container
- Update caCMCcaCert profile
- Install root CA admin cert
- Check cert requests in root CA
- Set up subordinate DS container
- Set up subordinate PKI container
- Install subordinate CA in subordinate container (step 1)
- Issue subordinate CA signing cert with CMC
- Install subordinate CA in subordinate container (step 2)
- Check subordinate CA signing cert
- Check subordinate CA OCSP signing cert
- Check subordinate CA audit signing cert
- Check subordinate subsystem cert
- Check subordinate SSL server cert
- Check subordinate CA admin cert
- Run PKI healthcheck
- Verify subordinate CA admin cert
- Check cert requests in subordinate CA
- Remove subordinate CA from subordinate container
- Remove root CA from root container

        ## Usage

            tmt run plan --name subca-cmc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
