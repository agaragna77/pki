        # rpminspect

        TMT port of `.github/workflows/rpminspect-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Set up PKI container
- Install rpminspect
- Copy SRPM and RPM packages
- Install rpminspect profile
- Check pki SRPM
- Check dogtag-pki RPM
- Check dogtag-pki-acme RPM
- Check dogtag-pki-base RPM
- Check dogtag-pki-ca RPM
- Check dogtag-pki-est RPM
- Check dogtag-pki-java RPM
- Check dogtag-pki-javadoc RPM
- Check dogtag-pki-kra RPM
- Check dogtag-pki-ocsp RPM
- Check dogtag-pki-server RPM
- Check dogtag-pki-tests RPM
- Check dogtag-pki-theme RPM
- Check dogtag-pki-tks RPM
- Check dogtag-pki-tools RPM
- Check dogtag-pki-tools-debuginfo RPM
- Check dogtag-pki-tps RPM
- Check pki-debugsource RPM
- Check python3-dogtag-pki RPM

        ## Usage

            tmt run plan --name rpminspect-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
