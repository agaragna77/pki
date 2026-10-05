        # KRA with sequential serial numbers

        TMT port of `.github/workflows/kra-sequential-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install KRA
- Run PKI healthcheck
- Verify KRA admin
- Verify KRA connector in CA
- Switch to RSNv3
- Verify cert key archival
- Check cert requests in CA
- Check certs in CA
- Check key requests in KRA
- Check keys in KRA
- Remove KRA
- Remove CA
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-sequential-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
