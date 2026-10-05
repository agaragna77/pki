        # CA CRL database

        TMT port of `.github/workflows/ca-crl-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Check pki ca-crl CLI help messages
- Install CA
- Configure caUserCert profile
- Check CRL issuing points
- Update CRL configuration
- Restart CA subsystem
- Run PKI healthcheck
- Initialize PKI client
- Check initial CRL
- Enroll user 1 cert
- Revoke user 1 cert
- Check CRL after user 1 cert revocation
- Check VLV usage in DS access log
- Unrevoke user 1 cert
- Check CRL after user 1 cert unrevocation
- Enroll user 2 cert
- Revoke user 2 cert
- Check CRL after user 2 cert revocation
- Wait for user 2 cert expiration
- Force CRL update after user 2 cert expiration
- Check CRL after user 2 cert expiration
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-crl-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
