        # Basic KRA

        TMT port of `.github/workflows/kra-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Check pki kra CLI help messages
- Install CA
- Check keywrap config in CA
- Check security domain config in CA
- Check CA admin cert
- Install KRA
- Check for warnings
- Check external commands
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check server.xml
- Check PKI server conf/alias dir after installation
- Check PKI server conf/Catalina/localhost dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check KRA base dir
- Check KRA conf dir
- Check keywrap config in KRA
- Check transport unit config in KRA
- Check storage unit config in KRA
- Check PKCS #12 encryption config in KRA
- Check PKI server system certs
- Check PKI server status
- Check KRA storage cert
- Check KRA transport cert
- Check subsystem cert
- Check SSL server cert
- Check CA admin cert after installing KRA
- Check security domain after installing KRA
- Run PKI healthcheck
- Check external commands
- Check CA info
- Check KRA info
- Check KRA admin
- Check KRA connector in CA
- Import transport cert
- Check initial key requests
- Check initial keys
- Generate AES key
- Check key requests after AES key generation
- Check keys after AES key generation
- Generate RSA key
- Check key requests after RSA key generation
- Check keys after RSA key generation
- Enroll cert with key archival
- Check key requests after enrollment
- Check keys after enrollment
- Check archived cert key
- Retrieve cert key
- Check key requests after retrieval
- Check keys after retrieval
- Deactivate cert key
- Check key requests after deactivation
- Check keys after deactivation
- Archive secret
- Check key requests after secret archival
- Check keys after secret archival
- Retrieve secret
- Check key requests after secret retrieval
- Check keys after secret retrieval
- Remove KRA
- Check for warnings
- Check external commands
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
