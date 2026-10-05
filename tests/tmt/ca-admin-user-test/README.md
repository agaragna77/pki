        # CA admin user

        TMT port of `.github/workflows/ca-admin-user-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check CA users
- Check CA groups
- Check CA admin user
- Check auth with CA admin password
- Change CA admin password
- Change CA admin password with file
- Remove CA admin password
- Check certs assigned to CA admin user
- Check auth with CA admin cert
- Unassign certs from CA admin user
- Reassign certs to CA admin user
- Check CA admin roles
- Remove CA admin role
- Authorization with CA admin cert should not work
- Restore CA admin role
- Authorization with CA admin cert should work again
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-admin-user-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
