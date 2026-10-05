        # KRA with ECC

        TMT port of `.github/workflows/kra-ecc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA with EC certs
- Install KRA with EC certs
- Check transport unit config in KRA
- Check storage unit config in KRA
- Check KRA storage cert
- Check KRA transport cert
- Check KRA audit signing cert
- Check subsystem cert
- Check SSL server cert
- Check KRA admin cert
- Check CA info
- Check KRA info
- Run PKI healthcheck
- Import CA signing cert
- Import KRA transport cert
- Check KRA admin
- Enable caECUserCert profile
- Enroll EC cert with key archival using CRMFPopClient
- Check key requests after key archival using CRMFPopClient
- Check keys after key archival using CRMFPopClient
- Check key record after key archival using CRMFPopClient
- Enroll EC cert with key archival using pki ca-cert-issue
- Check key requests after key archival using pki ca-cert-issue
- Check keys after key archival using pki ca-cert-issue
- Check key record after key archival using pki ca-cert-issue
- Remove KRA
- Remove CA
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-ecc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
