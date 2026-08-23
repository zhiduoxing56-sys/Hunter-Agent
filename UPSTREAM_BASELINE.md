# Hunter-Agent Upstream Baseline

## CAI

- Package: cai-framework
- Version: 0.5.10
- Source: official PyPI source distribution
- Source archive: cai_framework-0.5.10.tar.gz
- SHA256: de82ac5560eb01548f2e6d74e00d7718d4b8bfa04ab3843dc3645f50efe1d293
- Integration path: third_party/cai_framework-0.5.10
- Installation mode: editable local source installation

## Environment

- WSL2
- Ubuntu 24.04.3 LTS
- Python 3.12.3

## Baseline validation

The following were successfully validated on the development machine:

1. cai-framework 0.5.10 installed from the verified local source tree.
2. `import cai` succeeded.
3. `from cai.sdk.agents import Agent, Runner` succeeded.
4. No model or security-tool capability is implied by this baseline test.

## Version policy

CAI archive v1.1.5 is retained only as a research/reference implementation and is not the Hunter-Agent upstream baseline.

Hunter-Agent modifications are developed separately from the CAI upstream baseline.
