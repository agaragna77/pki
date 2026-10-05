        # Sub-CA with HSM

        TMT port of `.github/workflows/subca-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create root CA in NSS database
- Install dependencies
- Create SoftHSM token
- Install subordinate CA (step 1)
- Issue subordinate CA signing cert
- Install subordinate CA (step 2)
- Check system certs in internal token
- Check root CA signing cert in internal token
- Check ca_signing cert in internal token
- Check ca_ocsp_signing cert in internal token
- Check ca_audit_signing cert in internal token
- Check subsystem cert in internal token
- Check sslserver cert in internal token
- Check system certs in HSM
- Check ca_signing cert in HSM
- Check ca_ocsp_signing cert in HSM
- Check ca_audit_signing cert in HSM
- Check subsystem cert in HSM
- Run PKI healthcheck
- Check CA admin cert
- Check CA certs and requests
- Remove subordinate CA
- Remove SoftHSM token

        ## Usage

            tmt run plan --name subca-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
