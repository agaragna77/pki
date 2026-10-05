        # MCP Server

        TMT port of `.github/workflows/server-mcp-test.yml`.

        ## Steps

        - Clone PKI repository
- Retrieve PKI images
- Load PKI images
- Create network
- Set up DS container
- Set up PKI container
- Install CA
- Install MCP server
- Install LLM
- Install MCP CLI
- Configure MCP CLI
- Check MCP servers
- Check MCP resources
- Check MCP prompts
- Check MCP tools
- Find CA users

        ## Usage

            tmt run plan --name server-mcp-test

        ## Notes

        - Prepare phase builds pki-runner via `build-pki-runner.sh`.
        - Steps match GHA workflow; GHA-only actions are mapped to local equivalents
          or fail loudly with `exit 1`.
