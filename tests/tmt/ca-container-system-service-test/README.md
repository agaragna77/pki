        # CA container system service

        TMT port of `.github/workflows/ca-container-system-service-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Install Podman
- Configure Podman
- Load PKI images into root user's space
- Create shared folders in PKI user's home directory
- Create CA system service
- Run CA system service
- Get Tomcat flavor
- Check conf dir
- Check conf/alias dir
- Check conf/ca dir
- Check logs dir
- Check logs dir
- Check CA info
- Initialize CA database
- Create admin cert
- Add CA admin user
- Check CA admin user
- Check cert enrollment
- Check DS server systemd journal
- Check DS container logs
- Check CA container systemd journal
- Check CA container logs
- Check CA debug logs

        ## Usage

            tmt run plan --name ca-container-system-service-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
