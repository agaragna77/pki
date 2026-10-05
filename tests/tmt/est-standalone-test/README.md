        # EST on separate instance with provided certificates

        TMT port of `.github/workflows/est-standalone-test.yml`.

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
- Install EST (step 1)
- Issue subsystem cert
- Issue SSL server cert
- Stop CA
- Install EST (step 2)
- Check EST server base dir after installation
- Check EST server conf dir after installation
- Check EST server logs dir after installation
- Check EST server logs dir after installation
- Check EST conf dir
- Start CA
- Add EST subsystem user in CA
- Test CA certs
- Create EST user
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
- Check EST PKI server systemd journal
- Check CA debug log
- Check EST debug log

        ## Usage

            tmt run plan --name est-standalone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
