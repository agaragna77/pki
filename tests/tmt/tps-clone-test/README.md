        # TPS clone

        TMT port of `.github/workflows/tps-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install CA in primary PKI container
- Install KRA in primary PKI container
- Install TKS in primary PKI container
- Install TPS in primary PKI container
- Set up secondary DS container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Install KRA in secondary PKI container
- Install TKS in secondary PKI container
- Install TPS in secondary PKI container
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Check admin user
- Remove TPS from secondary PKI container
- Remove TKS from secondary PKI container
- Remove KRA from secondary PKI container
- Remove CA from secondary PKI container
- Remove TPS from primary PKI container
- Remove TKS from primary PKI container
- Remove KRA from primary PKI container
- Remove CA from primary PKI container
- Check primary DS server systemd journal
- Check primary DS container logs
- Check for primary PKI core dumps
- Check primary PKI server systemd journal
- Check primary CA debug log
- Check primary KRA debug log
- Check primary TKS debug log
- Check primary TPS debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check for secondary PKI core dumps
- Check secondary PKI server systemd journal
- Check secondary CA debug log
- Check secondary KRA debug log
- Check secondary TKS debug log
- Check secondary TPS debug log

        ## Usage

            tmt run plan --name tps-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
