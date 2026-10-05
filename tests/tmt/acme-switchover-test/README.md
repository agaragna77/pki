        # ACME server switchover

        TMT port of `.github/workflows/acme-switchover-test.yml`.

        ## Steps

        - Clone repository
- Retrieve ACME images
- Load ACME images
- Create network
- Set up DS container
- Set up PKI container
- Install CA in PKI container
- Install ACME in PKI container
- Initialize ACME database
- Initialize ACME realm
- Set up client container
- Install dependencies in client container
- Verify ACME directory before switchover
- Verify registration and enrollment before switchover
- Simulate ACME server switchover by replacing the baseURL parameter
- Verify ACME directory after switchover
- Verify renewal, revocation, account update and deactivation after switchover
- Remove ACME from PKI container
- Remove CA from PKI container
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check ACME debug log
- Check certbot log

        ## Usage

            tmt run plan --name acme-switchover-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
