        # PKI NSS CLI with Kryoptic

        TMT port of `.github/workflows/pki-nss-kryoptic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Install Kryoptic
- Create Kryoptic token
- Create NSS database
- Create CA signing key
- Check CA signing key in internal token
- Check CA signing key in HSM
- Create CA signing CSR with existing key
- Issue self-signed CA signing cert
- Import CA signing cert
- Check CA signing cert in internal token
- Check CA signing cert in HSM
- Create SSL server CSR with new key
- Issue SSL server cert
- Import SSL server cert
- Check SSL server key in internal token
- Check SSL server key in HSM
- Check SSL server cert in internal token
- Check SSL server cert in HSM
- Remove SSL server cert from internal token
- Remove SSL server cert and key from HSM
- Create audit signing CSR with new key
- Issue audit signing cert
- Import audit signing cert
- Check audit signing key
- Check audit signing cert
- Modify audit signing cert trust attributes
- Check audit signing cert trust attributes in internal token
- Check audit signing cert trust attributes in HSM
- Remove audit signing cert from internal token
- Remove audit signing cert and key from HSM
- Remove CA signing cert from internal token
- Remove CA signing cert from HSM
- Remove CA signing key
- Remove Kryoptic token

        ## Usage

            tmt run plan --name pki-nss-kryoptic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
