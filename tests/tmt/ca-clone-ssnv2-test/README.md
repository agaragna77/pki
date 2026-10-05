        # CA clone with SSNv2

        TMT port of `.github/workflows/ca-clone-ssnv2-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up primary DS container
- Set up primary PKI container
- Create primary CA
- Enable serial number management in primary CA
- Install admin cert in primary CA
- Check requests
- Check certs
- Check request range config in primary CA
- Check cert range config in primary CA
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Set up secondary DS container
- Set up secondary PKI container
- Create secondary CA
- Enable serial number management in secondary CA
- Install admin cert in secondary CA
- Check requests
- Check certs
- Check request range config in primary CA
- Check request range config in secondary CA
- Check cert range config in primary CA
- Check cert range config in secondary CA
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll 5 certs in secondary CA
- Check requests
- Check certs
- Check request range config in primary CA
- Check request range config in secondary CA
- Check cert range config in primary CA
- Check cert range config in secondary CA
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll a cert when cert range is exhausted in primary CA
- Enroll a cert when request range is exhausted in secondary CA
- Check requests
- Check certs
- Check request range config in primary CA
- Check request range config in secondary CA
- Check cert range config in primary CA
- Check cert range config in secondary CA
- Allocate new ranges
- Check request range config in primary CA
- Check request range config in secondary CA
- Check cert range config in primary CA
- Check cert range config in secondary CA
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Enroll 7 certs in primary CA
- Enroll 10 certs in secondary CA
- Check requests
- Check certs
- Check request range config in primary CA
- Check request range config in secondary CA
- Check cert range config in primary CA
- Check cert range config in secondary CA
- Check request range objects
- Check cert range objects
- Check request next range
- Check cert next range
- Allocate new request range for primary CA
- Enroll 10 certs in primary CA
- Check requests
- Check certs
- Allocate new request range for primary CA again
- Enroll 1 cert in primary CA
- Check requests
- Check certs
- Remove secondary CA
- Remove primary CA
- Check primary DS server systemd journal
- Check primary DS container logs
- Check primary PKI server systemd journal
- Check primary PKI server access log
- Check primary CA debug log
- Check secondary DS server systemd journal
- Check secondary DS container logs
- Check secondary PKI server systemd journal
- Check secondary PKI server access log
- Check secondary CA debug log

        ## Usage

            tmt run plan --name ca-clone-ssnv2-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
