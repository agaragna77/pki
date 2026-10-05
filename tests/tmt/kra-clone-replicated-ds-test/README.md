        # KRA clone with replicated DS

        TMT port of `.github/workflows/kra-clone-replicated-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install primary CA
- Check primary CA admin user
- Install primary KRA
- Check primary KRA admin user
- Set up secondary DS container
- Set up secondary PKI container
- Create secondary PKI server
- Create secondary CA subsystem
- Export CA certs and keys from primary CA
- Import system certs and keys into secondary CA
- Configure connection to CA database
- Create backend for CA in secondary DS
- Enable replication on primary DS
- Enable replication on secondary DS
- Create replication agreement on primary DS
- Create replication agreement on secondary DS
- Initializing replication agreement
- Create CA search indexes
- Install secondary CA
- Create secondary KRA subsystem
- Export KRA certs and keys from primary PKI container
- Import KRA system certs and keys into secondary KRA
- Configure connection to KRA database
- Create backend for KRA in secondary DS
- Enable KRA replication on primary DS
- Enable KRA replication on secondary DS
- Create replication agreement on primary DS
- Create replication agreement on secondary DS
- Initializing replication agreement
- Check schema in primary DS and secondary DS
- Check entries in primary KRA and secondary KRA
- Create KRA search indexes
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
- Check for secondary PKI core dumps
- Check PKI server systemd journal in secondary container
- Check secondary CA debug log
- Check secondary KRA debug log

        ## Usage

            tmt run plan --name kra-clone-replicated-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
