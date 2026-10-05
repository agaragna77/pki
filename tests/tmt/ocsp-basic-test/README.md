        # Basic OCSP

        TMT port of `.github/workflows/ocsp-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Check pki ocsp CLI help messages
- Install CA
- Check PKI system certs
- Check CA system certs
- Check security domain config in CA
- Install OCSP
- Check for warnings
- Check external commands
- Check PKI system certs
- Check OCSP system certs
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check server.xml
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check OCSP base dir
- Check OCSP conf dir
- Check PKI server status
- Check security domain config in OCSP
- Check OCSP signing cert
- Check subsystem cert
- Check SSL server cert
- Check OCSP admin cert
- Check OCSP publishing in CA
- Run PKI healthcheck
- Check external commands
- Initialize PKI client
- Prepare initial cert
- Check initial cert using pki ocsp-cert-verify
- Check initial cert using OCSPClient
- Check initial cert using OpenSSL
- Prepare revoked cert
- Check revoked cert using pki ocsp-cert-verify
- Check revoked cert using OCSPClient
- Check revoked cert using OpenSSL
- Prepare good cert
- Check good cert using pki ocsp-cert-verify
- Check good cert using OCSPClient
- Check good cert using OpenSSL
- Prepare non-existent cert
- Check OCSP responder non-existent cert using pki ocsp-cert-verify
- Check OCSP responder non-existent cert using OCSPClient
- Check OCSP responder non-existent cert using OpenSSL
- Check CA OCSP for non-existent cert using pki ocsp-cert-verify
- Check CA OCSP for non-existent cert using OCSPClient
- Check CA OCSP for non-existent cert using OpenSSL
- Create request with wrong CA
- Check request with wrong CA using pki ocsp-cert-verify
- Check request with wrong CA using OCSPClient
- Check request with wrong CA using OpenSSL
- Remove OCSP
- Check for warnings
- Check external commands
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check OCSP debug log

        ## Usage

            tmt run plan --name ocsp-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
