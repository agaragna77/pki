        # Standalone KRA

        TMT port of `.github/workflows/kra-standalone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up client container
- Set up DS container
- Set up CA container
- Install standalone CA
- Import CA certs into client
- Check CA admin
- Check CA users
- Check CA security domain
- Set up KRA container
- Install standalone KRA (step 1)
- Check KRA system and admin CSRs
- Issue KRA system and admin certs
- Check KRA system and admin certs
- Stop CA
- Install standalone KRA (step 2)
- Check KRA server status
- Check KRA system certs
- Run PKI healthcheck
- Start CA
- Import KRA certs into client
- Check KRA admin
- Check KRA users
- Check KRA security domain
- Check KRA connector in CA
- Check cert enrollment without KRA
- Add CA subsystem user in KRA
- Add KRA connector in CA
- Check cert enrollment with KRA
- Remove KRA
- Remove CA
- Check for client core dumps
- Check for CA core dumps
- Check CA systemd journal
- Check CA access log
- Check CA debug log
- Check for KRA core dumps
- Check KRA systemd journal
- Check KRA access log
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-standalone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
