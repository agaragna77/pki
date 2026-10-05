        # KRA on separate instance

        TMT port of `.github/workflows/kra-separate-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up root CA DS container
- Set up root CA container
- Install root CA
- Check root CA server status
- Check security domain config in root CA
- Check root CA certs
- Check root CA users
- Set up sub CA DS container
- Set up sub CA container
- Install sub CA
- Check sub CA server status
- Check sub CA certs
- Check sub CA users
- Check security domain config in sub CA
- Export subordinate CA cert bundle
- Install banner in sub CA container
- Verify sub CA admin
- Set up KRA DS container
- Set up KRA container
- Install KRA
- Check for warnings
- Check external commands
- Check KRA server status
- Check security domain config in KRA
- Check KRA certs
- Check KRA users
- Install banner in KRA container
- Verify KRA admin
- Verify KRA connector in sub CA
- Remove KRA
- Check for warnings
- Check external commands
- Remove sub CA
- Remove root CA
- Check for root CA core dumps
- Check PKI server systemd journal in root CA container
- Check root CA debug log
- Check for sub CA core dumps
- Check PKI server systemd journal in sub CA container
- Check sub CA debug log
- Check for KRA core dumps
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-separate-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
