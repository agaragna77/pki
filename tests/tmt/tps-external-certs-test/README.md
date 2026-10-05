        # TPS with external certs

        TMT port of `.github/workflows/tps-external-certs-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Initialize CA admin in CA container
- Set up KRA DS container
- Set up KRA container
- Install KRA in KRA container
- Set up TKS DS container
- Set up TKS container
- Install TKS in TKS container
- Set up TPS DS container
- Set up TPS container
- Install TPS in TPS container (step 1)
- Issue subsystem cert
- Issue SSL server cert
- Issue TPS audit signing cert
- Issue TPS admin cert
- Install TPS in TPS container (step 2)
- Run PKI healthcheck
- Check TPS admin
- Remove TPS
- Remove TKS
- Remove KRA
- Remove CA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check for CA core dumps
- Check CA systemd journal
- Check CA debug log
- Check KRA DS server systemd journal
- Check KRA DS container logs
- Check for KRA core dumps
- Check KRA systemd journal
- Check KRA debug log
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check for TKS core dumps
- Check TKS systemd journal
- Check TKS debug log
- Check TPS DS server systemd journal
- Check TPS DS container logs
- Check for TPS core dumps
- Check TPS systemd journal
- Check TPS debug log

        ## Usage

            tmt run plan --name tps-external-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
