        # OCSP clone

        TMT port of `.github/workflows/ocsp-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Install CA in primary PKI container
- Install OCSP in primary PKI container
- Set up CRL database in primary DS
- Remove default OCSP publishing in primary CA
- Configure CA cert publishing in primary CA
- Configure CRL publishing in primary CA
- Configure revocation info store in primary OCSP
- Configure primary PKI server
- Export system certs
- Set up secondary DS container
- Set up secondary PKI container
- Install CA in secondary PKI container
- Install OCSP in secondary PKI container
- Set up CRL database in secondary DS
- Configure CA cert publishing in secondary CA
- Configure CA cert publishing in secondary CA
- Configure revocation info store in secondary OCSP
- Configure secondary PKI server
- Check CA CS.cfg
- Check OCSP CS.cfg
- Set up tertiary DS container
- Set up tertiary PKI container
- Install CA in tertiary PKI container
- Install OCSP in tertiary PKI container
- Set up CRL database in tertiary DS
- Configure CA cert publishing in tertiary CA
- Configure CA cert publishing in tertiary CA
- Configure revocation info store in tertiary OCSP
- Configure tertiary PKI server
- Check CA CS.cfg
- Check OCSP CS.cfg
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Run PKI healthcheck in tertiary container
- Set up client container
- Install admin cert
- Check CA admin
- Check OCSP admin
- Enroll cert in primary CA
- Check CRL in primary DS
- Check CRL in secondary DS
- Check CRL in tertiary DS
- Check initial cert status in primary OCSP
- Check initial cert status in secondary OCSP
- Check initial cert status in tertiary OCSP
- Revoke cert in primary CA
- Check CRL in primary DS
- Check CRL in secondary DS
- Check CRL in tertiary DS
- Check revoked cert in primary OCSP
- Check revoked cert in secondary OCSP
- Check revoked cert in tertiary OCSP
- Unrevoke cert in primary CA
- Check CRL in primary DS
- Check CRL in secondary DS
- Check CRL in tertiary DS
- Check good cert in primary OCSP
- Check good cert in secondary OCSP
- Check good cert in tertiary OCSP
- Remove OCSP from tertiary PKI container
- Remove CA from tertiary PKI container
- Remove OCSP from secondary PKI container
- Remove CA from secondary PKI container
- Remove OCSP from primary PKI container
- Remove CA from primary PKI container
- Check primary DS server systemd journal
- Check primary DS container logs
- Check for primary PKI core dumps
- Check primary PKI server systemd journal
- Check primary PKI server access log
- Check primary CA debug log
- Check primary OCSP debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check for secondary PKI core dumps
- Check secondary PKI server systemd journal
- Check secondary PKI server access log
- Check secondary CA debug log
- Check secondary OCSP debug log
- Check tertiary DS server systemd journal
- Check tertiary DS container logs
- Check for tertiary PKI core dumps
- Check tertiary PKI server systemd journal
- Check tertiary PKI server access log
- Check tertiary CA debug log
- Check tertiary OCSP debug log

        ## Usage

            tmt run plan --name ocsp-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
