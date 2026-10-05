# IDM-8254: GHA↔TMT Parity Inventory

## Machine-readable inventory

- **Local:** `tests/tmt/gha-tmt-inventory.json`
- **Global report:** `/home/agaragna/Projects/JARVIS/POCs/IDM-8254/dogtag-gha-tmt-global-report.md`
- **Global inventory JSON:** `/home/agaragna/Projects/JARVIS/POCs/IDM-8254/dogtag-gha-tmt-global-inventory.json`

## Tooling

| Script | Purpose |
|--------|---------|
| `tests/tmt/bin/inventory-gha-tmt.py` | Scans GHA `*-test.yml`, writes `gha-tmt-inventory.json` |
| `tests/tmt/bin/generate-tmt-from-gha.py` | Generates TMT plan + test from each GHA workflow |
| `tests/tmt/bin/report-gha-vs-tmt.py` | Writes per-stem and global comparison reports |
| `tests/tmt/bin/build-pki-runner.sh` | Builds pki-runner image (TMT prepare phase) |

## Structure

Each GHA `*-test.yml` maps to:

    tests/tmt/plans/<stem>.fmf      — TMT plan (discover/prepare/execute/finish)
    tests/tmt/<stem>/main.fmf       — test metadata
    tests/tmt/<stem>/test.sh        — executable test (step banners match GHA)
    tests/tmt/<stem>/README.md      — human-readable overview

## Aggregate plan

    tests/tmt/plans/dogtag-gha-parity.fmf   — discovers all idm-8254 + dogtag tagged tests

## Notes

- Hand-ported tests (e.g. ca-basic-test) are preserved by the generator.
- Generated tests translate GHA steps to shell; GHA-only actions (checkout,
  cache, docker load) are mapped to local equivalents.
- Unknown GHA actions produce `exit 1` (fail loudly, never skip).
- Run `python3 tests/tmt/bin/inventory-gha-tmt.py` to refresh the inventory.
- Run `python3 tests/tmt/bin/report-gha-vs-tmt.py` to refresh all reports.
