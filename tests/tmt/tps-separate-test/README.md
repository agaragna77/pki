        # TPS on separate instance

        TMT port of `.github/workflows/tps-separate-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Install banner in CA container
- Set up KRA DS container
- Set up KRA container
- Install KRA in KRA container
- Verify there is no plain HTTP connectors in KRA
- Install banner in KRA container
- Set up TKS DS container
- Set up TKS container
- Install TKS in TKS container
- Verify there is no plain HTTP connectors in TKS
- Install banner in TKS container
- Set up TPS DS container
- Set up TPS container
- Install TPS in TPS container
- Check for warnings
- Check external commands
- Check TPS certs
- Verify there is no plain HTTP connectors in TPS
- Verify there is no plain HTTP ports in security domain but CA
- Install banner in TPS container
- Run PKI healthcheck
- Check TPS admin
- Check TPS subsystem user in CA
- Check TPS subsystem user in KRA
- Check TPS subsystem user in TKS
- Check TPS users
- Check connectors in TPS
- Check TPS connector in TKS
- Remove TPS
- Check for warnings
- Check external commands
- Remove TKS
- Remove KRA
- Remove CA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check for CA core dumps
- Check CA systemd journal
- Check CA access log
- Check CA debug log
- Check KRA DS server systemd journal
- Check KRA DS container logs
- Check for KRA core dumps
- Check KRA systemd journal
- Check KRA access log
- Check KRA debug log
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check for TKS core dumps
- Check TKS systemd journal
- Check TKS access log
- Check TKS debug log
- Check TPS DS server systemd journal
- Check TPS DS container logs
- Check for TPS core dumps
- Check TPS systemd journal
- Check TPS access log
- Check TPS debug log

        ## Usage

            tmt run plan --name tps-separate-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
