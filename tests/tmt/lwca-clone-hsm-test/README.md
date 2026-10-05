        # LWCA clone with HSM

        TMT port of `.github/workflows/lwca-clone-hsm-test.yml`.

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
- Install CA admin cert in primary PKI container
- Check authorities in primary CA
- Set up secondary DS container
- Set up secondary PKI container
- Set up SSH client in secondary PKI container
- Set up HSM client with p11-kit in secondary PKI container
- Install CA in secondary PKI container
- Install CA admin cert in secondary PKI container
- Check authorities in secondary CA
- Create LWCA in primary CA
- Check authorities in primary CA
- Check authorities in secondary CA
- Enroll with LWCA in primary CA
- Enroll with LWCA in secondary CA
- Remove LWCA from secondary CA
- Check authorities in secondary CA
- Check authorities in primary CA
- Remove secondary CA
- Remove primary CA
- Check SSH systemd journal in HSM container
- Check primary DS server systemd journal
- Check primary DS container logs
- Check primary PKI server systemd journal
- Check primary PKI server access log
- Check primary CA debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check secondary PKI server systemd journal
- Check secondary PKI server access log
- Check secondary CA debug log

        ## Usage

            tmt run plan --name lwca-clone-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
