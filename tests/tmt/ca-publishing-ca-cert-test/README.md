        # CA with CA cert publishing

        TMT port of `.github/workflows/ca-publishing-ca-cert-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Export CA cert
- Prepare CA cert publishing subtree
- Configure CA cert publishing
- Check published CA cert
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-publishing-ca-cert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
