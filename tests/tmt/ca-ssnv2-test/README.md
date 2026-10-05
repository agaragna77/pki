        # CA with SSNv2

        TMT port of `.github/workflows/ca-ssnv2-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Create CA with unsupported range format
- Cleanup CA installation
- Create CA
- Install admin cert
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enable serial number management
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll 10 certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll a cert when cert range is exhausted
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Allocate new ranges
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll 13 additional certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll a cert when request range is exhausted
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Allocate new ranges again
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll 7 additional certs
- Check requests
- Check certs
- Check request range config
- Check cert range config
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Create a request record with the next ID
- Enroll a cert with a conflicting request record ID
- Check request records
- Check conflicting request record
- Check cert records
- Create a cert with the next serial number
- Enroll a cert with a conflicting serial number
- Check requests
- Check certs
- Enroll a cert after conflicts
- Check requests
- Check certs
- Switch to RSNv3
- Enroll a cert with RSNv3
- Find all cert requests
- Find cert requests page 1 with REST API v1
- Find cert requests page 2 with REST API v1
- Find cert requests page 1 with REST API v2
- Find cert requests page 2 with REST API v2
- Find all certs
- Find certs page 1
- Find certs page 2
- Remove CA
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check PKI server access log
- Check CA debug log

        ## Usage

            tmt run plan --name ca-ssnv2-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
