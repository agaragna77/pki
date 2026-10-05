        # CA database pruning

        TMT port of `.github/workflows/ca-pruning-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Configure server cert profile
- Configure user cert profile
- Configure cert status update task
- Configure pruning job
- Restart CA subsystem
- Install CA admin cert
- Check initial certs and requests
- Enroll server cert
- Create incomplete server cert request
- Enroll user cert
- Create incomplete user cert request
- Check certs after enrollments
- Check requests after enrollments
- Wait for server cert expiration
- Check certs after server cert expiration
- Check requests after server cert expiration
- Start the first pruning
- Check certs after the first pruning
- Check requests after the first pruning
- Wait for user cert expiration
- Check certs after user cert expiration
- Check requests after user cert expiration
- Start the second pruning
- Check certs after the second pruning
- Check requests after the second pruning
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-pruning-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
