        # CA migration to container

        TMT port of `.github/workflows/ca-container-migration-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Install CA
- Set up client container
- Check CA info
- Check CA admin user
- Remove CA
- Install Podman
- Configure Podman
- Load PKI images into root user's space
- Create PKI CA systemd service
- Run PKI CA systemd service
- Get Tomcat flavor
- Check conf dir
- Check conf/alias dir
- Check conf/ca dir
- Check logs dir
- Check logs dir
- Check CA admin user
- Check cert enrollment
- Check DS server systemd journal
- Check DS container logs
- Check PKI Tomcat systemd journal
- Check PKI CA systemd journal
- Check PKI CA container logs
- Check CA debug logs

        ## Usage

            tmt run plan --name ca-container-migration-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
