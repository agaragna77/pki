        # IPA clone

        TMT port of `.github/workflows/ipa-clone-test.yml`.

        ## Steps

        - Clone repository
- Retrieve IPA images
- Load IPA images
- Create network
- Run primary container
- Install IPA server in primary container
- Update primary PKI server configuration
- Check CA database config in primary IPA
- Check CA CRL config in primary IPA
- Check primary IPA server config
- Install KRA in primary container
- Check KRA connector config
- Check primary IPA server config after KRA installation
- Run secondary container
- Install IPA client in secondary container
- Promote IPA client into IPA replica in secondary container
- Install CA in secondary container
- Update secondary PKI server configuration
- Check CA database config in secondary IPA
- Check CA CRL config in primary IPA
- Check CA CRL config in secondary IPA
- Install KRA in secondary container
- Check schema in primary DS and secondary DS
- Check replication managers on primary DS
- Check replication managers on secondary DS
- Check replica objects on primary DS
- Check replica objects on secondary DS
- Check replication agreements on primary DS
- Check replication agreements on secondary DS
- Check KRA connector config in primary CA
- Check KRA connector config in secondary CA
- Check IPA server config
- Change renewal master
- Check primary CA config
- Check secondary CA config
- Check CA CSR copied correctly
- Check CRL generation config
- Change CRL master
- Check CRL generation config in primary CA
- Check CRL generation config in secondary CA
- Run PKI healthcheck in primary container
- Run PKI healthcheck in secondary container
- Check PKI database user in primary CA
- Check PKI database user in secondary CA
- Verify CA admin
- Check subca replication from primary
- Remove subca from clone
- Check IPA CA install log in primary container
- Check IPA KRA install log in primary container
- Check HTTPD access logs in primary container
- Check HTTPD error logs in primary container
- Check DS server systemd journal in primary container
- Check DS access logs in primary container
- Check DS error logs in primary container
- Check DS security logs in primary container
- Check CA pkispawn log in primary container
- Check KRA pkispawn log in primary container
- Check PKI server systemd journal in primary container
- Check PKI server access log in primary container
- Check CA debug log in primary container
- Remove IPA server from primary container
- Check CA pkidestroy log in primary container
- Check KRA pkidestroy log in primary container
- Check IPA config after removing primary server
- Check CRL generator after removing primary server
- Check KRA connector after removing primary server
- Check IPA CA install log in secondary container
- Check IPA KRA install log in secondary container
- Check HTTPD access logs in secondary container
- Check HTTPD error logs in secondary container
- Check DS server systemd journal in secondary container
- Check DS access logs in secondary container
- Check DS error logs in secondary container
- Check DS security logs in secondary container
- Check CA pkispawn log in secondary container
- Check KRA pkispawn log in secondary container
- Check PKI server systemd journal in secondary container
- Check PKI server access log in secondary container
- Check CA debug log in secondary container
- Remove IPA server from secondary container
- Check CA pkidestroy log in secondary container
- Check KRA pkidestroy log in secondary container

        ## Usage

            tmt run plan --name ipa-clone-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
