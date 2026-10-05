        # TKS clone

        TMT port of `.github/workflows/tks-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install CA in primary PKI container
- Install TKS in primary PKI container
- Set up secondary DS container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Install TKS in secondary PKI container
- Verify TKS admin in secondary PKI container
- Set up tertiary DS container
- Set up tertiary PKI container
- Install CA in tertiary PKI container
- Install TKS in tertiary PKI container
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Run PKI healthcheck in tertiary container
- Verify TKS admin in tertiary PKI container
- Remove TKS from tertiary PKI container
- Remove CA from tertiary PKI container
- Remove TKS from secondary PKI container
- Remove CA from secondary PKI container
- Remove TKS from primary PKI container
- Remove CA from primary PKI container
- Check primary DS server systemd journal
- Check primary DS container logs
- Check primary PKI server systemd journal
- Check primary CA debug log
- Check primary TKS debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check secondary PKI server systemd journal
- Check secondary CA debug log
- Check secondary TKS debug log
- Check tertiary DS server systemd journal
- Check tertiary DS container logs
- Check tertiary PKI server systemd journal
- Check tertiary CA debug log
- Check tertiary TKS debug log

        ## Usage

            tmt run plan --name tks-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
