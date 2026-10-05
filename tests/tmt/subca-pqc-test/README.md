        # SubCA with PQC

        TMT port of `.github/workflows/subca-pqc-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root CA DS container
- Set up root CA container
- Get Fedora version
- Set up root CA crypto-policies
- Install root CA
- Set up sub CA DS container
- Set up sub CA container
- Set up sub CA crypto-policies
- Install sub CA
- Configure sub CA
- Check sub CA signing cert request
- Check sub CA OCSP signing cert request
- Check sub CA audit signing cert request
- Check sub CA subsystem cert request
- Check sub CA SSL server cert request
- Check sub CA admin cert request
- Check sub CA signing cert
- Check sub CA OCSP signing cert
- Check sub CA audit signing cert
- Check sub CA subsystem cert
- Check sub CA SSL server cert
- Check sub CA admin cert
- Run sub CA healthcheck
- Check external commands
- Check sub CA admin user
- Check sub CA signing cert chain
- Check sub CA OCSP signing cert chain
- Check sub CA audit signing cert chain
- Check sub CA subsystem cert chain
- Check sub CA SSL server cert chain
- Check sub CA admin cert chain
- Check sub CA signing cert status
- Check sub CA OCSP signing cert status
- Check sub CA audit signing cert status
- Check sub CA subsystem cert status
- Check sub CA SSL server cert status
- Check sub CA admin cert status
- Check sub CA signing cert usage
- Check sub CA OCSP signing cert usage
- Check sub CA audit signing cert usage
- Check sub CA subsystem cert usage
- Check sub CA SSL server cert usage
- Check sub CA admin cert usage
- Remove sub CA
- Remove root CA
- Check root CA DS server systemd journal
- Check root CA DS container logs
- Check root CA systemd journal
- Check root CA access log
- Check root CA debug log
- Check sub CA DS server systemd journal
- Check sub CA DS container logs
- Check sub CA systemd journal
- Check sub CA access log
- Check sub CA debug log

        ## Usage

            tmt run plan --name subca-pqc-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
