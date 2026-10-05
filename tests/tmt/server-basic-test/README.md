        # Basic server

        TMT port of `.github/workflows/server-basic-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up server container
- Get Fedora version
- Get Tomcat flavor
- Check Tomcat lib dir
- Check PKI lib dir
- Check PKI lib dir
- Check PKI server common lib dir
- Check PKI server lib dir
- Check ROOT webapp dir
- Check ROOT webapp WEB-INF dir
- Check PKI webapp dir
- Check PKI webapp WEB-INF dir
- Check PKI webapp WEB-INF/classes dir
- Check PKI webapp WEB-INF/lib dir
- Check CA webapp dir
- Check CA webapp WEB-INF dir
- Check CA webapp WEB-INF/classes dir
- Check CA webapp WEB-INF/lib dir
- Check KRA webapp dir
- Check KRA webapp WEB-INF dir
- Check KRA webapp WEB-INF/classes dir
- Check KRA webapp WEB-INF/lib dir
- Check OCSP webapp dir
- Check OCSP webapp WEB-INF dir
- Check OCSP webapp WEB-INF/classes dir
- Check OCSP webapp WEB-INF/lib dir
- Check TKS webapp dir
- Check TKS webapp WEB-INF dir
- Check TKS webapp WEB-INF/classes dir
- Check TKS webapp WEB-INF/lib dir
- Check TPS webapp dir
- Check TPS webapp WEB-INF dir
- Check TPS webapp WEB-INF/lib dir
- Check ACME webapp dir
- Check ACME webapp WEB-INF dir
- Check ACME webapp WEB-INF/classes dir
- Check ACME webapp WEB-INF/lib dir
- Check EST webapp dir
- Check EST webapp WEB-INF dir
- Check EST webapp WEB-INF/classes dir
- Check EST webapp WEB-INF/lib dir
- Check pki-server CLI help message
- Check pki-server CLI version
- Check pki-server CLI with wrong option
- Check pki-server CLI with wrong sub-command
- Check pki-server create CLI help message
- Create pki-tomcat server
- Start pki-tomcat server
- Check pki-tomcat server base dir after installation
- Check pki-tomcat server common dir after installation
- Check pki-tomcat server conf dir after installation
- Check pki-tomcat server.xml
- Check pki-tomcat tomcat.conf
- Check PKI server conf/Catalina/localhost dir after installation
- Check pki-tomcat server logs dir after installation
- Check pki-tomcat server logs dir after installation
- Check pki-tomcat webapps
- Check pki-tomcat subsystems
- Check HTTP connection to pki-tomcat server
- Stop pki-tomcat server
- Remove pki-tomcat server
- Check pki-tomcat server base dir after removal
- Check pki-tomcat server conf dir after removal
- Check pki-tomcat server logs dir after removal
- Check pki-tomcat server logs dir after removal
- Create tomcat@pki server
- Start tomcat@pki server
- Check tomcat@pki server base dir after installation
- Check tomcat@pki server conf dir after installation
- Check tomcat@pki server.xml
- Check tomcat@pki tomcat.conf
- Check tomcat@pki server logs dir after installation
- Check tomcat@pki server logs dir after installation
- Check HTTP connection to tomcat@pki server
- Stop tomcat@pki server
- Remove tomcat@pki server
- Check tomcat@pki server base dir after removal
- Check tomcat@pki server conf dir after removal
- Check tomcat@pki server logs dir after removal
- Check tomcat@pki server logs dir after removal

        ## Usage

            tmt run plan --name server-basic-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
