        # CA with SSNv1

        TMT port of `.github/workflows/ca-ssnv1-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create CA
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Enable serial number management
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Install admin cert
- Enroll 10 certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Enroll a cert when cert range is exhausted
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Allocate new ranges
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Enroll 13 additional certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Enroll a cert when request range is exhausted
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Allocate new ranges again
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Enroll 10 additional certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request next range
- Check cert next range
- Check request range objects
- Check cert range objects
- Switch to legacy2
- Check request range config
- Check cert range config
- Check the radix configured for the new generator
- Check ranges entry is configured in a new tree
- Check request range objects for SSNv1
- Check request range objects for SSNv2
- Check request next range for SSNv1
- Check request next range for SSNv2
- Check cert range objects for SSNv1
- Check cert range objects for SSNv2
- Check cert next range for SSNv1
- Check cert next range for SSNv2
- Enroll additional certs
- Check request range config
- Check cert range config
- Check request range objects for SSNv1
- Check request range objects for SSNv2
- Check request next range for SSNv1
- Check request next range for SSNv2
- Check cert range objects for SSNv1
- Check cert range objects for SSNv2
- Check cert next range for SSNv1
- Check cert next range for SSNv2
- Check requests
- Check certs
- Switch to RSNv3
- Enroll a cert with RSNv3
- Check requests
- Check certs
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name ca-ssnv1-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
