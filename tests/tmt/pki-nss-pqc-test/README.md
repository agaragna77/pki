        # PKI NSS CLI with PQC

        TMT port of `.github/workflows/pki-nss-pqc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Create NSS database
- Create CA signing key
- Check CA signing key
- Create CA signing CSR with existing key
- Issue self-signed CA signing cert
- Import CA signing cert
- Check CA signing cert
- Create SSL server CSR with new key
- Issue SSL server cert
- Import SSL server cert
- Check SSL server key
- Check SSL server cert
- Remove SSL server cert and key
- Create audit signing CSR with new key
- Issue audit signing cert
- Import audit signing cert
- Check audit signing key
- Check audit signing cert
- Modify audit signing cert trust flags
- Check audit signing cert trust flags
- Remove audit signing cert and key
- Create KRA storage CSR with new key
- Issue KRA storage cert
- Import KRA storage cert
- Check KRA storage key
- Check KRA storage cert
- Remove KRA storage cert and key
- Remove CA signing cert
- Remove CA signing key

        ## Usage

            tmt run plan --name pki-nss-pqc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
