        # CA with custom profile

        TMT port of `.github/workflows/ca-profile-custom-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up authentication database
- Set up PKI container
- Install CA
- Configure UserDirEnrollment
- Restart CA subsystem
- Install CA admin cert
- Retrieve caDirUserCert profile
- Create custom profile
- Add custom profile
- Enable custom profile
- Check custom profile info
- Check custom profile config
- Check custom profile config file
- Create cert request
- Issue cert
- Disable custom profile
- Remove custom profile
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name ca-profile-custom-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
