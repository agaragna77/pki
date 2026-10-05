        # TKS on separate instance

        TMT port of `.github/workflows/tks-separate-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Install banner in CA container
- Set up TKS DS container
- Set up TKS container
- Install TKS in TKS container
- Check for warnings
- Check external commands
- Check TKS certs
- Install banner in TKS container
- Run PKI healthcheck
- Verify TKS admin
- Remove TKS
- Check for warnings
- Check external commands
- Remove CA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA systemd journal
- Check CA debug log
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check TKS systemd journal
- Check TKS debug log

        ## Usage

            tmt run plan --name tks-separate-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
