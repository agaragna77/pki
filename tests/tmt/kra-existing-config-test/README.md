        # KRA with existing config

        TMT port of `.github/workflows/kra-existing-config-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Install CA
- Install KRA
- Check system certs
- Check KRA admin
- Remove KRA
- Check PKI server base dir after first removal
- Check PKI server conf dir after first removal
- Check PKI server logs dir after first removal
- Check PKI server logs dir after first removal
- Install KRA again
- Check PKI server config after second installation
- Check KRA config after second installation
- Check system certs again
- Check KRA admin again
- Check CA debug log
- Check KRA debug log
- Remove KRA again
- Remove CA
- Check PKI server base dir after second removal
- Check PKI server conf dir after second removal
- Check PKI server logs dir after second removal
- Check PKI server systemd journal

        ## Usage

            tmt run plan --name kra-existing-config-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
