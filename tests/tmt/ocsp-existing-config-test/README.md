        # OCSP with existing config

        TMT port of `.github/workflows/ocsp-existing-config-test.yml`.

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
- Install OCSP
- Check system certs
- Check OCSP admin
- Remove OCSP
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Install OCSP again
- Check PKI server config after second installation
- Check OCSP config after second installation
- Check system certs again
- Check OCSP admin again
- Check CA debug log
- Check OCSP debug log
- Remove OCSP again
- Remove CA
- Check PKI server base dir after second removal
- Check PKI server conf dir after second removal
- Check PKI server logs dir after second removal
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal

        ## Usage

            tmt run plan --name ocsp-existing-config-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
