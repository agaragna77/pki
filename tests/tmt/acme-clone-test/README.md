        # ACME clone

        TMT port of `.github/workflows/acme-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA
- Set up primary ACME DS container
- Set up primary ACME container
- Install primary ACME
- Check primary ACME database config
- Check primary ACME issuer config
- Check primary ACME realm config
- Check primary ACME system certs
- Initialize primary ACME database
- Initialize primary ACME realm
- Check primary ACME DS
- Set up secondary ACME DS container
- Set up secondary ACME container
- Install secondary ACME
- Check secondary ACME database config
- Check secondary ACME issuer config
- Check secondary ACME realm config
- Check secondary ACME system certs
- Set up ACME database and realm replication
- Check secondary ACME DS
- Set up client container
- Install certbot in client container
- Register account in primary ACME
- Check accounts in secondary ACME
- Move acme.example.com to secondary ACME
- Enroll client cert against secondary ACME
- Check client cert
- Check orders in primary ACME
- Check authorizations in primary ACME
- Check challenges in primary ACME
- Check certs in primary ACME
- Remove secondary ACME
- Remove primary ACME
- Remove CA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA server systemd journal
- Check CA access log
- Check CA debug log
- Check primary ACME DS server systemd journal
- Check primary ACME DS container logs
- Check primary ACME server systemd journal
- Check primary ACME access log
- Check primary ACME debug log
- Check secondary ACME DS server systemd journal
- Check secondary ACME DS container logs
- Check secondary ACME server systemd journal
- Check secondary ACME access log
- Check secondary ACME debug log
- Check certbot log

        ## Usage

            tmt run plan --name acme-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
