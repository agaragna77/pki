        # CA with ML-DSA CRMFPopClient

        TMT port of `.github/workflows/ca-mldsa-CRMFPopClient-test.yml`.

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
- Set up CA admin
- Enable caMLDSAUserCert profile
- Enroll ML-DSA cert using CRMFPopClient without POP
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-mldsa-CRMFPopClient-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
