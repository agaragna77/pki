        # CA with PQC

        TMT port of `.github/workflows/ca-pqc-test.yml`.

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
- Check system cert keys
- Check CA signing cert
- Check CA OCSP signing cert
- Check CA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Enable audit signing
- Run PKI healthcheck
- Check authenticating as CA admin user
- Check CA admin cert
- Check issuing SSL server cert with RSA key
- Check issuing SSL server cert with ML-DSA-65 key
- Check audit get signed
- Enable caMLDSAUserCert profile
- Enroll OCSP test cert
- Check good cert OCSP response signed with ML-DSA
- Revoke OCSP test cert
- Check revoked cert OCSP response signed with ML-DSA
- Generating new sslserver certificate with CMC
- Remove CA and cleanup home
- Create ML-DSA-87 configuration
- Install CA with ML-DSA-87 and default buffer (65536 for PQC)
- Check CA signing cert
- Check authenticating as CA admin user
- Check CA admin cert
- Remove CA
- Install CA with ML-DSA-87 with legacy buffer size
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log

        ## Usage

            tmt run plan --name ca-pqc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
