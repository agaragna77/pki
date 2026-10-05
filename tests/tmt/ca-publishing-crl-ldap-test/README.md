        # CA with LDAP-based CRL publishing

        TMT port of `.github/workflows/ca-publishing-crl-ldap-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Prepare CRL publishing subtree
- Configure CRL publishing
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Run PKI healthcheck
- Initialize PKI client
- Check initial CRL
- Check CRL after update
- Check CRL after cert revocation
- Check CRL after cert unrevocation
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-publishing-crl-ldap-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
