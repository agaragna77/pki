        # CA with user cert publishing

        TMT port of `.github/workflows/ca-publishing-user-cert-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Prepare publishing subtree
- Configure user cert publishing
- Configure caUserCert profile
- Configure cert status update task
- Configure unpublish expired job to run automatically
- Restart CA subsystem
- Check CA admin
- Check user 1 before enrollment
- Enroll user 1 cert
- Check user 1 after enrollment
- Revoke user 1 cert
- Check user 1 after revocation
- Unrevoke user 1 cert
- Check user 1 after unrevocation
- Wait for user 1 cert expiration
- Check user 1 after expiration
- Configure unpublish expired job to run manually
- Restart CA subsystem
- Check user 2 before enrollment
- Enroll user 2 cert
- Check user 2 after enrollment
- Wait for user 2 cert expiration
- Check user 2 after expiration
- Run unpublish job manually
- Check user 2 after manual execution
- Remove CA
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-publishing-user-cert-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
