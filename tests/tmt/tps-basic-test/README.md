        # Basic TPS

        TMT port of `.github/workflows/tps-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Check pki tps CLI help messages
- Install CA
- Install KRA
- Install TKS
- Install TPS
- Check for warnings
- Check external commands
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check server.xml
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check TPS base dir
- Check TPS conf dir
- Check TPS server status
- Check PKI server system certs
- Check subsystem cert
- Check SSL server cert
- Check TPS admin cert
- Run PKI healthcheck
- Check external commands
- Check TPS admin
- Check connectors in TPS
- Set up TPS authentication and misc cfg settings
- Check pki tps-client
- Check tpsclient
- Add token for testuser1
- Format testuser1 token using pki tps-client
- Enroll testuser1 token using pki tps-client
- Reset PIN for testuser1 token using pki tps-client
- Find testuser1 key in KRA
- Add token for testuser2
- Format testuser2 token using tpsclient
- Enroll testuser2 token using tpsclient
- Reset PIN for testuser2 token using tpsclient
- Find testuser2 key in KRA
- Remove TPS
- Check for warnings
- Check external commands
- Remove TKS
- Remove KRA
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check KRA debug log
- Check TKS debug log
- Check TPS debug log

        ## Usage

            tmt run plan --name tps-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
