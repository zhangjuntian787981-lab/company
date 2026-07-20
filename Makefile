PYTHON ?= python3
CANDIDATE_BINARY := $(CURDIR)/artifacts/cliproxyapi-v7.2.80-candidate
GATEWAY_BINARY := $(CURDIR)/artifacts/claude-budget-gateway-v7.2.80-candidate

.PHONY: test cloud-setup self-check repair-source-check source-boundary-check source-validation build-candidate candidate-bottle-check synthetic-oauth-check claude-code-e2e gateway-e2e context-e2e launchd-isolated-check soak-local real-upstream final-report check-prod clean

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -v

cloud-setup:
	./scripts/setup-cloud.sh

check-prod:
	PYTHONPATH=. ./scripts/check-prod-untouched.sh --check-known

self-check:
	PYTHONPATH=. $(PYTHON) -m harness.runner

repair-source-check source-boundary-check:
	PYTHONPATH=. $(PYTHON) ./scripts/run-v7.2.80-boundary-tests.py

source-validation:
	PYTHONPATH=. $(PYTHON) ./scripts/run_source_validation.py

build-candidate:
	PYTHONPATH=. $(PYTHON) ./scripts/build_reproducible_candidate.py

candidate-bottle-check:
	PYTHONPATH=. $(PYTHON) -m harness.runner --cliproxyapi-binary $(CANDIDATE_BINARY) --gateway-binary $(GATEWAY_BINARY)

synthetic-oauth-check:
	PYTHONPATH=. $(PYTHON) ./scripts/run-synthetic-oauth.py --cliproxyapi-binary $(CANDIDATE_BINARY)

claude-code-e2e gateway-e2e context-e2e:
	PYTHONPATH=. $(PYTHON) ./scripts/run-claude-code-e2e.py --cliproxyapi-binary $(CANDIDATE_BINARY) --gateway-binary $(GATEWAY_BINARY)

launchd-isolated-check:
	@echo "separate explicit approval is required before creating any temporary launchd label" >&2
	@exit 2

soak-local:
	PYTHONPATH=. $(PYTHON) ./scripts/run-local-soak.py

real-upstream:
	PYTHONPATH=. $(PYTHON) ./scripts/run-real-upstream.py

final-report:
	PYTHONPATH=. $(PYTHON) ./scripts/generate-final-report.py

clean:
	rm -rf __pycache__ harness/__pycache__ tests/__pycache__
