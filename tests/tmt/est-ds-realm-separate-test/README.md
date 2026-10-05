        # EST with ds realm on separate instance

        TMT port of `.github/workflows/est-ds-realm-separate-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA
- Initialize PKI client
- Set up EST DS container
- Set up EST container
- Get Fedora version
- Get Tomcat flavor
- Set up EST user DB
- Install EST
- Check EST server base dir after installation
- Check EST server conf dir after installation
- Check EST server logs dir after installation
- Check EST server logs dir after installation
- Check EST conf dir
- Test CA certs
- Add EST user
- Add EST user to EST Users group
- Install est client
- Enroll certificate
- Remove EST
- Remove CA
- Check EST server base dir after removal
- Check EST server conf dir after removal
- Check EST server logs dir after removal
- Check EST server logs dir after removal
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA PKI server systemd journal
- Check CA debug log
- Check for EST core dumps
- Check EST PKI server systemd journal
- Check EST debug log

        ## Usage

            tmt run plan --name est-ds-realm-separate-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
