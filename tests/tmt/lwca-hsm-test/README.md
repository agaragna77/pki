        # LWCA with HSM

        TMT port of `.github/workflows/lwca-hsm-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install dependencies
- Create SoftHSM token
- Install CA
- Check admin user
- Check host CA's LDAP entry
- Check certs and keys in internal token
- Check certs and keys in HSM
- Check host CA
- Create lightweight CA
- Check lightweight CA's LDAP entry
- Check certs and keys in internal token
- Check certs and keys in HSM
- Check enrollment against lightweight CA
- Remove lightweight CA
- Check lightweight CA's LDAP entry
- Check certs and keys in internal token
- Check certs and keys in HSM
- Check CA debug logs
- Remove CA
- Remove SoftHSM token

        ## Usage

            tmt run plan --name lwca-hsm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
