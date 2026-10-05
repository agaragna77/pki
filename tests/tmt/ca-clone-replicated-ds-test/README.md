        # CA clone with replicated DS

        TMT port of `.github/workflows/ca-clone-replicated-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install primary CA
- Check primary CA admin user
- Set up secondary DS container
- Set up secondary PKI container
- Create secondary PKI server
- Create secondary CA subsystem
- Export system certs and keys from primary CA
- Import system certs and keys into secondary CA
- Configure connection to CA database
- Preparing DS backend
- Enable replication on primary DS
- Enable replication on secondary DS
- Create replication agreement on primary DS
- Create replication agreement on secondary DS
- Initializing replication agreement
- Check schema in primary DS and secondary DS
- Check entries in primary DS and secondary DS
- Create search indexes
- Install secondary CA
- Check system certs in primary CA and secondary CA
- Check CS.cfg in primary CA after cloning
- Check CS.cfg in secondary CA
- Check secondary CA admin user
- Check users in primary CA and secondary CA
- Check certs in primary CA and secondary CA
- Check security domain in primary CA and secondary CA
- Remove CA from secondary PKI container
- Remove CA from primary PKI container
- Check for primary PKI core dumps
- Check for secondary PKI core dumps

        ## Usage

            tmt run plan --name ca-clone-replicated-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
