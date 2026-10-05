        # CA with caDirPinUserCert profile

        TMT port of `.github/workflows/ca-profile-caDirPinUserCert-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Add LDAP users
- Set up PKI container
- Set up PIN database
- Add PIN schema
- Add PIN manager
- Add PIN access control
- Check PIN schema
- Check PIN manager
- Check PIN access control
- Generate user PINs
- Install CA
- Configure PinDirEnrollment
- Enable caDirPinUserCert profile
- Restart CA subsystem
- Check CA admin
- Check enrollment using pki ca-cert-issue
- Check enrollment using XML
- Check enrollment using JSON
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-profile-caDirPinUserCert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
