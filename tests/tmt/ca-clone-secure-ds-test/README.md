        # CA clone with secure DS

        TMT port of `.github/workflows/ca-clone-secure-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Create DS signing cert in primary PKI container
- Create DS server cert in primary PKI container
- Import DS certs into primary DS container
- Install CA in primary PKI container
- Check NSS database in primary PKI container
- Create external cert in primary PKI container
- Import external cert into primary PKI server
- Verify DS connection in primary PKI container
- Verify users and DS hosts in primary PKI container
- Check cert requests in primary CA
- Set up secondary DS container
- Set up secondary PKI container
- Import DS signing cert into secondary PKI container
- Create DS server cert in secondary PKI container
- Import DS certs into secondary DS container
- Export certs for cloning from primary PKI container
- Install CA in secondary PKI container
- Check NSS database in secondary PKI container
- Check external cert in secondary PKI server
- Run PKI healthcheck in primary PKI container
- Run PKI healthcheck in secondary PKI container
- Verify DS connection in secondary PKI container
- Verify users and SD hosts in secondary PKI container
- Check cert requests in secondary CA
- Remove CA from secondary PKI container
- Check for warnings
- Check external commands
- Re-install CA in secondary PKI container
- Check NSS database in secondary PKI container again
- Remove external cert from secondary PKI server
- Remove CA from secondary PKI container
- Remove CA from primary PKI container

        ## Usage

            tmt run plan --name ca-clone-secure-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
