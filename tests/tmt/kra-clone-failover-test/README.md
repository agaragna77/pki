        # KRA clone failover

        TMT port of `.github/workflows/kra-clone-failover-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA
- Update CA server configuration
- Set up client container
- Import certs for client
- Check admin access to CA
- Set up primary KRA DS container
- Set up primary KRA container
- Install primary KRA
- Update primary KRA server configuration
- Check KRA connector in CA
- Import certs for client
- Check admin access to primary KRA
- Check cert enrollment with primary KRA
- Check access logs in primary KRA
- Set up secondary KRA DS container
- Set up secondary KRA container
- Install secondary KRA
- Update secondary KRA server configuration
- Check KRA connector in CA
- Check admin access to secondary KRA
- Check cert enrollment with multiple KRAs
- Check access logs in primary KRA
- Shut down primary KRA
- Check cert enrollment with KRA failover
- Check access logs in secondary KRA
- Remove primary KRA
- Check cert enrollment with secondary KRA
- Check access logs in secondary KRA
- Remove secondary KRA
- Remove CA
- Check for CA core dumps
- Check CA systemd journal
- Check CA access log
- Check CA debug log
- Check for primary KRA core dumps
- Check primary KRA systemd journal
- Check primary KRA access log
- Check primary KRA debug log
- Check for secondary KRA core dumps
- Check secondary KRA systemd journal
- Check secondary KRA access log
- Check secondary KRA debug log

        ## Usage

            tmt run plan --name kra-clone-failover-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
