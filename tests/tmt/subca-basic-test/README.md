        # Basic Sub-CA

        TMT port of `.github/workflows/subca-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root DS container
- Set up root PKI container
- Install root CA in root container
- Check root CA server status
- Check root CA system certs
- Install banner in root container
- Set up subordinate DS container
- Set up subordinate PKI container
- Install subordinate CA in subordinate container
- Check sub CA server status
- Check sub CA system certs
- Install banner in subordinate container
- Check CA signing cert
- Check CA OCSP signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Run PKI healthcheck
- Check external commands
- Verify CA admin
- Check cert requests in subordinate CA
- Check integrate root OCSP validation from SubCA
- Remove subordinate CA from subordinate container
- Remove root CA from root container

        ## Usage

            tmt run plan --name subca-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
