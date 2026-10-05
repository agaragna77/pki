        # Basic TKS

        TMT port of `.github/workflows/tks-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Check pki tks CLI help messages
- Install CA
- Install TKS
- Check for warnings
- Check external commands
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check server.xml
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check TKS base dir
- Check TKS conf dir
- Check TKS server status
- Check PKI server system certs
- Check subsystem cert
- Check SSL server cert
- Check TKS admin cert
- Run PKI healthcheck
- Check external commands
- Verify TKS admin
- Remove TKS
- Check for warnings
- Check external commands
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check TKS debug log

        ## Usage

            tmt run plan --name tks-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
