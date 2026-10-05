        # CA with caDirUserCert profile

        TMT port of `.github/workflows/ca-profile-caDirUserCert-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Add LDAP users
- Set up PKI container
- Install CA
- Configure UserDirEnrollment
- Enable caDirUserCert profile
- Restart CA subsystem
- Set up CA admin
- Check enrollment using pki ca-cert-issue
- Check enrollment using XML
- Check enrollment using JSON
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-profile-caDirUserCert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
