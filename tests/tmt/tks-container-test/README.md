        # TKS container

        TMT port of `.github/workflows/tks-container-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Create shared folders
- Set up client container
- Set up CA container
- Wait for CA to start
- Check CA info
- Set up CA DS container
- Initialize CA database
- Import CA signing cert into CA database
- Import CA OCSP signing cert into CA database
- Import CA subsystem cert into CA database
- Import SSL server cert into CA database
- Create admin cert
- Add CA admin user
- Add CA admin user into CA groups
- Check CA admin user
- Create TKS subsystem cert
- Create TKS SSL server cert
- Prepare TKS certs and keys
- Set up TKS container
- Wait for TKS container to start
- Get Fedora version
- Get Tomcat flavor
- Check TKS conf dir
- Check TKS conf/tks dir
- Check TKS logs dir
- Check TKS logs dir
- Check TKS info
- Set up TKS DS container
- Set up TKS database
- Add TKS admin user
- Add TKS admin user into TKS groups
- Check TKS admin user
- Restart TKS
- Check TKS admin user again
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA container logs
- Check CA debug logs
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check TKS container logs
- Check TKS debug logs
- Check client container logs

        ## Usage

            tmt run plan --name tks-container-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
