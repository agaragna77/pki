        # CA with caStorageCert profile

        TMT port of `.github/workflows/ca-profile-caStorageCert-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Set up CA admin
- Enroll cert using PKCS10Client
- Enroll cert using CRMFPopClient without POP
- Enroll cert using CRMFPopClient with POP
- Enroll cert using PKI CLI with PKCS #10 request
- Enroll cert using PKI CLI with CRMF request without POP
- Enroll cert using PKI CLI with CRMF request with POP
- Remove CA
- Check for core dumps
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-profile-caStorageCert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
