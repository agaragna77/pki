        # Server backup

        TMT port of `.github/workflows/server-backup-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Run PKI healthcheck before backup
- Set up client container
- Set up PKI client
- Check CA database before backup
- Back up PKI server
- Remove PKI container
- Recreate PKI container
- Restore PKI server
- Run PKI healthcheck after restore
- Check CA database after restore
- Remove CA

        ## Usage

            tmt run plan --name server-backup-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
