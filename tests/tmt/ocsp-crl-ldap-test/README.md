        # OCSP with LDAP-based CRL publishing

        TMT port of `.github/workflows/ocsp-crl-ldap-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Install CA admin cert in CA container
- Set up OCSP DS container
- Set up OCSP container
- Install OCSP in OCSP container (step 1)
- Issue OCSP signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue OCSP audit signing cert
- Issue OCSP admin cert
- Install OCSP in OCSP container (step 2)
- Install OCSP admin cert in OCSP container
- Prepare CRL publishing subtree
- Configure CA cert publishing in CA
- Configure CA cert publishing in CA
- Configure revocation info store in OCSP
- Check OCSP responder with no CRLs
- Check OCSP responder with initial CRL
- Check OCSP responder with revoked cert
- Check OCSP responder with unrevoked cert
- Remove OCSP from OCSP container
- Remove CA from CA container
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA systemd journal
- Check CA access log
- Check CA debug log
- Check OCSP DS server systemd journal
- Check OCSP DS container logs
- Check OCSP systemd journal
- Check OCSP access log
- Check OCSP debug log

        ## Usage

            tmt run plan --name ocsp-crl-ldap-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
