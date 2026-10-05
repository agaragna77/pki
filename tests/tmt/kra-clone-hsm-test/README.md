        # KRA clone with HSM

        TMT port of `.github/workflows/kra-clone-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install dependencies in primary PKI container
- Create SoftHSM token in primary PKI container
- Install CA in primary PKI container
- Install KRA in primary PKI container
- Check system certs in internal token
- Check system certs in HSM
- Copy keys from primary PKI container
- Set up secondary DS container
- Set up secondary PKI container
- Install dependencies in secondary PKI container
- Copy keys to secondary PKI container
- Install CA in secondary PKI container
- Install KRA in secondary PKI container
- Check system certs in internal token
- Check system certs in HSM
- Check CS.cfg in primary KRA after cloning
- Check CS.cfg in secondary KRA
- Check KRA admin in secondary PKI container
- Set up tertiary DS container
- Set up tertiary PKI container
- Install dependencies in tertiary PKI container
- Copy keys to tertiary PKI container
- Install CA in tertiary PKI container
- Install KRA in tertiary PKI container
- Check for warnings
- Check external commands
- Check system certs in internal token
- Check system certs in HSM
- Check CS.cfg in secondary KRA after cloning
- Check CS.cfg in tertiary KRA
- Check KRA admin in tertiary PKI container
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Run PKI healthcheck in tertiary container
- Remove KRA from tertiary PKI container
- Check for warnings
- Check external commands
- Remove CA from tertiary PKI container
- Remove KRA from secondary PKI container
- Remove CA from secondary PKI container
- Remove KRA from primary PKI container
- Remove CA from primary PKI container
- Check for primary PKI core dumps
- Check PKI server systemd journal in primary container
- Check primary CA debug log
- Check primary KRA debug log
- Check for secondary PKI core dumps
- Check PKI server systemd journal in secondary container
- Check secondary CA debug log
- Check secondary KRA debug log
- Check for tertiary PKI core dumps
- Check PKI server systemd journal in tertiary container
- Check tertiary CA debug log
- Check tertiary KRA debug log

        ## Usage

            tmt run plan --name kra-clone-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
