        # CA clone with HSM

        TMT port of `.github/workflows/ca-clone-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up HSM container
- Set up SoftHSM in HSM container
- Set up SSH server in HSM container
- Set up primary DS container
- Set up primary PKI container
- Set up SSH client in primary PKI container
- Set up HSM client with p11-kit in primary PKI container
- Install CA in primary PKI container
- Check system certs in internal token
- Check system certs in HSM
- Set up secondary DS container
- Set up secondary PKI container
- Set up SSH client in secondary PKI container
- Set up HSM client with p11-kit in secondary PKI container
- Install CA in secondary PKI container
- Check system certs in internal token
- Check system certs in HSM
- Check CS.cfg in primary CA after cloning
- Check CS.cfg in secondary CA
- Set up tertiary DS container
- Set up tertiary PKI container
- Set up SSH client in tertiary PKI container
- Set up HSM client with p11-kit in tertiary PKI container
- Install CA in tertiary PKI container
- Check for warnings
- Check external commands
- Check system certs in internal token
- Check system certs in HSM
- Check CS.cfg in secondary CA after cloning
- Check CS.cfg in tertiary CA
- Remove CA from tertiary PKI container
- Check for warnings
- Check external commands
- Remove CA from secondary PKI container
- Remove CA from primary PKI container
- Check SSH systemd journal in HSM container

        ## Usage

            tmt run plan --name ca-clone-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
