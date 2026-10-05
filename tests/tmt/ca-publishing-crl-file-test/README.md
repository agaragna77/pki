        # CA with file-based CRL publishing

        TMT port of `.github/workflows/ca-publishing-crl-file-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Configure caUserCert profile
- Configure caServerCert profile
- Prepare CRL publishing location
- Configure file-based CRL publishing
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Run PKI healthcheck
- Check CA admin
- Create user cert
- Create server cert
- Check initial CRL
- Check CRL after update
- Check user cert after update
- Check server cert after update
- Revoke user cert
- Revoke server cert
- Check CRL after revocation
- Check user cert after revocation
- Check server cert after revocation
- Unrevoke user cert
- Unrevoke server cert
- Check CRL after unrevocation
- Check user cert after unrevocation
- Check server cert after unrevocation
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-publishing-crl-file-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
