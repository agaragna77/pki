        # HTTPS connector with JKS file

        TMT port of `.github/workflows/server-https-jks-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up server container
- Create PKI server
- Create SSL server cert
- Create HTTPS connector with JKS file
- Start PKI server
- Set up client container
- Wait for PKI server to start
- Stop PKI server
- Remove PKI server

        ## Usage

            tmt run plan --name server-https-jks-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
