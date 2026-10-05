        # Sub-CA clone

        TMT port of `.github/workflows/subca-clone-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root CA container
- Create root CA in NSS database
- Set up primary DS container
- Set up primary sub-CA container
- Install dependencies
- Create SoftHSM token
- Install primary sub-CA (step 1)
- Issue primary sub-CA signing cert
- Install primary sub-CA (step 2)
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
- Check primary sub-CA admin
- Set up secondary DS container
- Set up secondary sub-CA container
- Install dependencies in secondary PKI container
- Copy keys to secondary PKI container
- Install secondary sub-CA
- Check CS.cfg in primary sub-CA after cloning
- Check CS.cfg in secondary sub-CA
- Check system certs in internal token
- Check root CA signing cert in internal token
- Check ca_signing cert in internal token
- Check ca_audit_signing cert in internal token
- Check sslserver cert in internal token
- Check system certs in HSM
- Check ca_signing cert in HSM
- Check ca_ocsp_signing cert in HSM
- Check ca_audit_signing cert in HSM
- Check subsystem cert in HSM
- Run PKI healthcheck
- Check secondary sub-CA admin
- Check users in primary sub-CA and secondary sub-CA
- Check certs in primary sub-CA and secondary sub-CA
- Remove secondary sub-CA
- Remove primary sub-CA

        ## Usage

            tmt run plan --name subca-clone-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
