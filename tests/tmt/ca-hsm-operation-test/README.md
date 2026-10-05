        # CA with HSM and custom operation key flags

        TMT port of `.github/workflows/ca-hsm-operation-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install dependencies
- Create SoftHSM token
- Install CA with HSM and no sign flag
- Check the install with no sign ops failed
- Install CA with HSM reintroducing sign flag
- Remove CA
- Remove SoftHSM token
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-hsm-operation-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
