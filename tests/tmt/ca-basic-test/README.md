        # Basic CA

        TMT port of `.github/workflows/ca-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Check pki CLI help messages
- Get Tomcat flavor
- Install CA
- Check for warnings
- Check external commands
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check server.xml
- Check tomcat.conf
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check /etc/sysconfig/pki-tomcat
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check CA base dir
- Check CA conf dir
- Check CA server status
- Check webapps
- Check subsystems
- Check CA certs and keys
- Check CA signing cert request
- Check CA OCSP signing cert request
- Check CA audit signing cert request
- Check subsystem cert request
- Check SSL server cert request
- Check admin cert request
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert
- Check CA audit events
- Run PKI healthcheck
- Check external commands
- Check CA admin user
- Check CA signing cert chain
- Check CA OCSP signing cert chain
- Check CA audit signing cert chain
- Check CA subsystem cert chain
- Check CA SSL server cert chain
- Check CA admin cert chain
- Check CA signing cert status
- Check CA OCSP signing cert status
- Check CA audit signing cert status
- Check subsystem cert status
- Check SSL server cert status
- Check CA admin cert status
- Check CA signing cert usage
- Check CA OCSP signing cert usage
- Check CA audit signing cert usage
- Check subsystem cert usage
- Check SSL server cert usage
- Check CA admin cert usage
- Check default audit config
- Enable audit log signing
- Test CA certs
- Check certs in DS
- Check users in DS
- Check cert requests in DS
- Test CA auditor
- Check CA profiles
- Remove CA
- Check for warnings
- Check external commands
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name ca-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
