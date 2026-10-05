        # KRA with existing DS database

        TMT port of `.github/workflows/kra-existing-ds-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA
- Initialize CA admin in CA container
- Set up KRA container
- Create PKI server
- Issue KRA storage cert
- Issue KRA transport cert
- Issue KRA audit signing cert
- Issue subsystem cert
- Issue SSL server cert
- Issue KRA admin cert
- Create KRA subsystem
- Set up KRA DS container
- Configure connection to KRA database
- Check connection to KRA database
- Initialize KRA database
- Add KRA search indexes
- Rebuild KRA search indexes
- Add KRA admin user
- Assign roles to KRA admin user
- Install KRA
- Check security domain config in KRA
- Check KRA certs
- Check KRA storage cert in server's NSS database
- Check KRA transport cert in server's NSS database
- Check KRA audit signing cert in server's NSS database
- Check subsystem cert in server's NSS database
- Check SSL server cert in server's NSS database
- Check KRA users
- Check KRA admin user
- Check KRA connector in CA
- Verify cert key archival
- Remove KRA from KRA container
- Remove CA from CA container
- Check PKI server systemd journal in CA container
- Check CA debug log
- Check PKI server systemd journal in KRA container
- Check KRA debug log

        ## Usage

            tmt run plan --name kra-existing-ds-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
