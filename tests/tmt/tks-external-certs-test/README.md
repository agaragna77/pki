        # TKS with external certs

        TMT port of `.github/workflows/tks-external-certs-test.yml`.

        ## Steps

        - Clone repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up CA DS container
- Set up CA container
- Install CA in CA container
- Initialize CA admin in CA container
- Set up TKS DS container
- Set up TKS container
- Install TKS in TKS container (step 1)
- Issue subsystem cert
- Issue SSL server cert
- Issue TKS audit signing cert
- Issue TKS admin cert
- Install TKS in TKS container (step 2)
- Run PKI healthcheck
- Verify TKS admin
- Remove TKS
- Remove CA
- Check CA DS server systemd journal
- Check CA DS container logs
- Check CA systemd journal
- Check CA debug log
- Check TKS DS server systemd journal
- Check TKS DS container logs
- Check TKS systemd journal
- Check TKS debug log

        ## Usage

            tmt run plan --name tks-external-certs-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
