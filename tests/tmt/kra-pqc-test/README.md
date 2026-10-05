        # KRA with PQC and ML-KEM

        TMT port of `.github/workflows/kra-pqc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Enable ML-DSA in default crypto-policies
- Install CA
- Check CA admin cert
- Install KRA
- Check for warnings
- Check external commands
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
- Check CA info
- Check KRA info
- Run PKI healthcheck
- Check external commands
- Check KRA admin
- Check KRA connector in CA
- Import transport cert
- Check initial key requests
- Check initial keys
- Enroll cert with ML-KEM key archival
- Check key requests after enrollment
- Check keys after enrollment
- Verify cert import into original NSS database
- Check archived ML-KEM key
- Retrieve ML-KEM key
- Verify archived ML-KEM PKCS
- Check key requests after retrieval
- Check keys after retrieval
- Remove KRA
- Check for warnings
- Check external commands
- Remove CA
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-pqc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
