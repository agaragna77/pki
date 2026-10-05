        # EST with ds realm

        TMT port of `.github/workflows/est-ds-realm-test.yml`.

        ## Steps

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
- Create EST user
- Add EST user to EST Users group
- Test CA certs
- Install est client
- Enroll certificate with user/password
- Enroll new certificate with certificate but using different CN
- Add certificate to the user
- Enroll new certificate with certificate
- Re-Enroll new certificate with certificate
- Re-Enroll new certificate with csr using different subject
- Enroll new certificate with certificate but using different subject
- Disable EST subject check for enroll
- Enroll certificate with user/password but using different subject and EST check disabled
- Enroll new certificate with certificate but using different subject and EST check disabled
- Create CA agent user with est-test-user cert
- Enroll certificate with user/password but using different subject and EST check disabled
- Enroll new certificate with certificate but using different subject and EST check disabled and agent client
- Remove agent
- Modify CA Subject Name policy
- Enroll certificate with user/password but using different subject, check disabled and no CA Subject constraint
- Enroll new certificate with certificate but using different subject and check disabled and no CA Subject constraint
- Re-Enroll new certificate with csr using different subject
- Remove EST
- Remove CA
- Check PKI server base dir after removal
- Check PKI server conf dir after removal
- Check PKI server logs dir after removal
- Check PKI server logs dir after removal
- Check DS server systemd journal
- Check DS container logs
- Check for PKI core dumps
- Check PKI server systemd journal
- Check CA debug log
- Check EST debug log

        ## Usage

            tmt run plan --name est-ds-realm-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
