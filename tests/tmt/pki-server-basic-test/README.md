        # Basic PKI Server CLI

        TMT port of `.github/workflows/pki-server-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up runner container
- Check pki-server CLI help message
- Check pki-server CLI version
- Check pki-server CLI with wrong option
- Check pki-server CLI with wrong sub-command
- Check pki-server instance help messages
- Check pki-server password help messages
- Check pki-server cert help messages
- Check pki-server http-connector help messages
- Check pki-server http-connector-host help messages
- Check pki-server http-connector-cert help messages
- Check pki-server webapp help messages
- Check pki-server subsystem help messages
- Check pki-server ca-sd help messages
- Check pki-server ca-sd-subsystem help messages
- Check pki-server ca-config help messages
- Check pki-server ca-user help messages
- Check pki-server ca-user-cert help messages
- Check pki-server ca-user-role help messages
- Check pki-server ca-group help messages
- Check pki-server ca-group-member help messages
- Check pki-server ca-id-generator help messages
- Check pki-server ca-db-access help messages
- Check pki-server ca-audit-config help messages
- Check pki-server ca-audit-event help messages
- Check pki-server ca-audit-file help messages

        ## Usage

            tmt run plan --name pki-server-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
