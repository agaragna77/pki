        # TPS container

        TMT port of `.github/workflows/tps-container-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Set up CA container
- Check CA info
- Set up CA DS container
- Set up CA database
- Import CA signing cert into CA database
- Import CA OCSP signing cert into CA database
- Import CA subsystem cert into CA database
- Import SSL server cert into CA database
- Create admin cert
- Add CA admin user
- Add admin user into CA groups
- Create KRA storage cert
- Create KRA transport cert
- Create KRA subsystem cert
- Create KRA SSL server cert
- Prepare KRA certs and keys
- Set up KRA container
- Wait for KRA container to start
- Check KRA info
- Set up KRA DS container
- Set up KRA database
- Add KRA admin user
- Add KRA admin user into KRA groups
- Add CA subsystem user in KRA
- Assign roles to CA subsystem user
- Configure KRA connector in CA
- Create TKS subsystem cert
- Create TKS SSL server cert
- Prepare TKS certs and keys
- Set up TKS container
- Wait for TKS container to start
- Check TKS info
- Set up TKS DS container
- Set up TKS database
- Add TKS admin user
- Add TKS admin user into TKS groups
- Import KRA transport cert into TKS
- Create shared secret in TKS
- Add TPS connector in TKS
- Create TPS subsystem cert
- Create TPS SSL server cert
- Prepare TPS certs and keys
- Set up TPS container
- Wait for TPS container to start
- Get Fedora version
- Get Tomcat flavor
- Check TPS conf dir
- Check TPS conf/tps dir
- Check TPS logs dir
- Check TPS logs dir
- Check TPS info
- Set up TPS DS container
- Set up TPS database
- Add TPS admin user
- Add TPS admin user into TPS groups
- Add TPS subsystem user in CA
- Add CA connector in TPS
- Add TPS subsystem user in KRA
- Add KRA connector in TPS
- Add TPS subsystem user in TKS
- Add TKS connector in TPS
- Import shared secret into TPS
- Set up user auth database for TPS
- Configure TPS for testing
- Restart CA
- Check CA admin user after restart
- Restart KRA
- Check KRA admin user after restart
- Restart TKS
- Check TKS admin user after restart
- Check TPS connector in TKS after restart
- Restart TPS
- Check TPS admin user after restart
- Check TPS subsystem user in CA after restart
- Check CA connector in TPS after restart
- Check TPS subsystem user in KRA after restart
- Check KRA connector in TPS after restart
- Check TPS subsystem user in TKS after restart
- Check TKS connector in TPS after restart
- Check shared secret in TPS after restart
- Add token
- Format token
- Enroll token
- Reset PIN
- Check user key in KRA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA container logs
- Check CA access log
- Check CA debug logs
- Check KRA DS server systemd journal
- Check KRA DS container logs
- Check KRA container logs
- Check KRA access log
- Check KRA debug logs
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check TKS container logs
- Check TKS access log
- Check TKS debug logs
- Check TPS DS server systemd journal
- Check TPS DS container logs
- Check TPS container logs
- Check TPS access log
- Check TPS debug logs
- Check client container logs

        ## Usage

            tmt run plan --name tps-container-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
