        # Server upgrade

        TMT port of `.github/workflows/server-upgrade-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Add upgrade script
- Run pki-server upgrade without any servers
- Run pki-server db-schema-upgrade without any servers
- Install CA
- Check CA admin cert
- Run pki-server upgrade with one server
- Run pki-server db-schema-upgrade with one server
- Restart PKI server after upgrade
- Check CA admin cert after upgrade
- Remove CA

        ## Usage

            tmt run plan --name server-upgrade-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
