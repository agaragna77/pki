        # EST with postgresql realm

        TMT port of `.github/workflows/est-postgresql-realm-test.yml`.

        ## Steps

        - Install dependencies
- Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Get Fedora version
- Get Tomcat flavor
- Install CA
- Initialize PKI client
- Create postgresql certificates
- Create postgresql Docker file
- Build postgrsql image with certificates
- Deploy postgresql
- Connect DB container to network
- Set up database drivers
- Set up EST user DB
- Install EST
- Check EST backend config
- Check EST authorizer config
- Check EST realm config
- Check webapps
- Check PKI server base dir after installation
- Check PKI server conf dir after installation
- Check PKI server logs dir after installation
- Check PKI server logs dir after installation
- Check EST conf dir
- Test CA certs
- Add EST user
- Install est client
- Enroll certificate
- Enroll new certificate with certificate but using different CN
- Add certificate to the user
- Enroll new certificate with certificate
- Re-Enroll new certificate with certificate
- Enroll new certificate with certificate but using different subject
- Disable EST subject for enroll
- Enroll certificate with user/password but using different subject and EST check disabled
- Enroll new certificate with certificate but using different subject and EST check disabled
- Create CA agent user with est-test-user cert
- Enroll certificate with user/password but using different subject and EST check disabled
- Enroll new certificate with certificate but using different subject and EST check disabled and agent client
- Remove agent
- Modify CA Subject Name policy
- Enroll certificate with user/password but using different subject, check disabled and no CA Subject contraint
- Enroll new certificate with certificate but using different subject and check disabled and no CA Subject contraint
- Remove EST
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check PKI server systemd journal
- Check CA debug log
- Check EST debug log

        ## Usage

            tmt run plan --name est-postgresql-realm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
