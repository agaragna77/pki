        # KRA clone

        TMT port of `.github/workflows/kra-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install primary CA in primary PKI container
- Install primary KRA in primary PKI container
- Check schema in primary DS
- Check initial replica range config in primary KRA
- Check initial KRA replica range objects
- Check initial KRA replica next range
- Set up secondary DS container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Install KRA in secondary PKI container
- Check schema in secondary DS
- Check KRA replica object on primary DS
- Check KRA replica object on secondary DS
- Check KRA replication agreement on primary DS
- Check KRA replication agreement on secondary DS
- Check replica range config in primary KRA after cloning
- Check replica range config in secondary KRA
- Check KRA replica range objects
- Check KRA replica next range
- Verify KRA admin in secondary PKI container
- Set up tertiary DS container
- Set up tertiary PKI container
- Install CA in tertiary PKI container
- Install KRA in tertiary PKI container
- Check schema in tertiary DS
- Check replication manager on tertiary DS
- Check KRA replica object on tertiary DS
- Check KRA replication agreement on tertiary DS
- Check replica range config in secondary KRA after cloning
- Check replica range config in tertiary KRA
- Check KRA replica range objects
- Check KRA replica next range
- Verify KRA admin in tertiary PKI container
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Run PKI healthcheck in tertiary container
- Remove KRA from tertiary PKI container
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

            tmt run plan --name kra-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
