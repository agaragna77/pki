        # CA clone

        TMT port of `.github/workflows/ca-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up client container
- Set up primary DS container
- Set up primary PKI container
- Install CA in primary PKI container
- Check schema in primary DS
- Check initial replica range config in primary CA
- Check initial CA replica range objects
- Check initial CA replica next range
- Check primary CA server status
- Check primary CA system certs
- Check admin cert for primary CA
- Check SD hosts in primary PKI server
- Check users in primary CA
- Check cert requests in primary CA
- Check certs in primary CA
- Set up secondary DS container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Check for warnings
- Check external commands
- Check secondary CA server status
- Check secondary CA system certs
- Check schema in secondary DS
- Check replication manager on primary DS
- Check replication manager on secondary DS
- Check replica object on primary DS
- Check CA replica object on secondary DS
- Check CA replication agreement on primary DS
- Check CA replication agreement on secondary DS
- Check CS.cfg in primary CA after cloning
- Check CS.cfg in secondary CA
- Check replica range config in primary CA after cloning
- Check replica range config in secondary CA
- Check CA replica range objects
- Check CA replica next range
- Check admin cert for secondary CA
- Check SD hosts in secondary PKI server
- Check users in secondary CA
- Check cert requests in secondary CA
- Check certs in secondary CA
- Set up tertiary DS container
- Set up tertiary PKI container
- Install CA in tertiary PKI container
- Check schema in tertiary DS
- Check replication manager on tertiary DS
- Check CA replica object on tertiary DS
- Check CA replication agreement on tertiary DS
- Check CS.cfg in secondary CA after cloning
- Check CS.cfg in tertiary CA
- Check replica range config in secondary CA after cloning
- Check replica range config in tertiary CA
- Check CA replica range objects
- Check CA replica next range
- Check admin cert for tertiary CA
- Check SD hosts in tertiary PKI server
- Check users in tertiary CA
- Check cert requests in tertiary CA
- Check certs in tertiary CA
- Enroll cert in primary CA
- Check initial cert status in primary OCSP
- Check initial cert status in secondary OCSP
- Check initial cert status in tertiary OCSP
- Revoke cert in primary CA
- Check revoked cert in primary OCSP
- Check revoked cert in secondary OCSP
- Check revoked cert in tertiary OCSP
- Unrevoke cert in tertiary CA
- Check good cert in primary OCSP
- Check good cert in secondary OCSP
- Check good cert in tertiary OCSP
- Remove CA from tertiary PKI container
- Remove CA from secondary PKI container
- Check for warnings
- Check external commands
- Remove CA from primary PKI container
- Check primary DS server systemd journal
- Check primary DS container logs
- Check for primary PKI core dumps
- Check primary PKI server systemd journal
- Check primary PKI server access log
- Check primary CA debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check for secondary PKI core dumps
- Check secondary PKI server systemd journal
- Check secondary PKI server access log
- Check secondary CA debug log
- Check tertiary DS server systemd journal
- Check tertiary DS container logs
- Check for tertiary PKI core dumps
- Check tertiary PKI server systemd journal
- Check tertiary PKI server access log
- Check tertiary CA debug log

        ## Usage

            tmt run plan --name ca-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
