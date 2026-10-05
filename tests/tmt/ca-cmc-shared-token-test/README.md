        # CA with CMC shared token

        TMT port of `.github/workflows/ca-cmc-shared-token-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install CA admin cert
- Create issuance protection cert
- Configure shared token auth
- Generate shared token for user
- Issue user cert with shared token
- Revoke user cert with shared token
- Check CMC_USER_SIGNED_REQUEST_SIG_VERIFY events
- Check CERT_STATUS_CHANGE_REQUEST_PROCESSED events
- Check CMC_REQUEST_RECEIVED events
- Check CMC_RESPONSE_SENT events
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-cmc-shared-token-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
