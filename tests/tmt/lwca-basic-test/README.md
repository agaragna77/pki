        # Basic LWCA

        TMT port of `.github/workflows/lwca-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Check pki ca-authority CLI help messages
- Install CA
- Check admin user
- Check host CA's LDAP entry
- Check certs and keys in NSS database
- Check host CA
- Create lightweight CAs
- Check authority LDAP entries
- Check certs and keys in NSS database
- Check enrollment against lightweight CA
- Remove lightweight CAs
- Check authority LDAP entries
- Check certs and keys in NSS database
- Check CA debug logs
- Remove CA

        ## Usage

            tmt run plan --name lwca-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
