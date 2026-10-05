        # SCEP responder

        TMT port of `.github/workflows/scep-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Check default FlatFileAuth config
- Check default SCEP responder config
- Enable SCEP responder
- Set up client container
- Get client IP address
- Register client
- Get CA certificate
- Generate cert request
- Enroll cert with DES3
- Check issued cert
- Check cert key
- Check client registration
- Configure SCEP responder with AES
- Register client
- Generate cert request
- Enroll cert with AES
- Check issued cert
- Check cert key
- Check client registration
- Remove CA from PKI container
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name scep-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
