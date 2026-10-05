        # KRA clone with shared DS

        TMT port of `.github/workflows/kra-clone-shared-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install CA in primary PKI container
- Install KRA in primary PKI container
- Install admin cert in primary PKI container
- Export certs and keys from primary PKI container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Install KRA in secondary PKI container
- Check system certs in primary KRA and secondary KRA
- Check CS.cfg in primary KRA after cloning
- Check CS.cfg in secondary KRA
- Install admin cert in secondary PKI container
- Check users in primary KRA and secondary KRA
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Remove KRA from secondary PKI container
- Remove CA from secondary PKI container
- Remove KRA from primary PKI container
- Remove CA from primary PKI container
- Check for primary PKI core dumps
- Check PKI server systemd journal in primary container
- Check primary CA debug log
- Check primary KRA debug log
- Check for secondary container core dump
- Check PKI server systemd journal in secondary container
- Check secondary CA debug log
- Check secondary KRA debug log

        ## Usage

            tmt run plan --name kra-clone-shared-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
