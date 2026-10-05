        # CA with caInternalAuthTransportCert profile

        TMT port of `.github/workflows/ca-profile-caInternalAuthTransportCert-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Enable ML-DSA in default crypto-policies
- Install CA
- Configure caInternalAuthTransportCert profile
- Set up CA admin
- Create SD session
- Enroll cert using CRMFPopClient without POP
- Enroll cert using PKI CLI with CRMF request without POP
- Remove SD session
- Remove CA
- Check for core dumps
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-profile-caInternalAuthTransportCert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
