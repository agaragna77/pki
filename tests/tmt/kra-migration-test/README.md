        # KRA migration

        TMT port of `.github/workflows/kra-migration-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up first DS container
- Set up first PKI container
- Install first CA
- Check first CA admin
- Install first KRA
- Check first KRA admin
- Check cert enrollment with key archival
- Check archived key in first KRA
- Check key retrieval from first KRA
- Set up second DS container
- Set up second PKI container
- Install second CA
- Check second CA admin
- Install second KRA
- Check second KRA admin
- Rewrap archived keys
- Import keys into second KRA
- Check archived key in second KRA
- Check key retrieval from second KRA
- Remove first KRA
- Remove first CA
- Remove second KRA
- Remove second CA
- Check for first PKI core dumps
- Check first CA debug log
- Check first KRA debug log
- Check for second PKI core dumps
- Check second CA debug log
- Check second KRA debug log

        ## Usage

            tmt run plan --name kra-migration-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
