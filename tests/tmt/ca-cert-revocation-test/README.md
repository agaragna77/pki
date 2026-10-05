        # CA cert revocation

        TMT port of `.github/workflows/ca-cert-revocation-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Update CA configuration
- Check CA admin
- Create test certs
- Check cert revocation using pki ca-cert commands
- Check cert revocation using revoker tool
- Check CA agent cert revocation
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-cert-revocation-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
