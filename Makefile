# Swarm test targets.
.PHONY: test benchmark lab-test bash-test

# Unit + integration suite (server).
test:
	cd server && pytest -q

# FP/FN benchmark — gates on precision >= 0.90 (Phase 2).
benchmark:
	pytest tests/benchmark/ -q -s

# End-to-end lab: spin up juice-shop + httpbin, run the real engine (Phase 1).
# Skips automatically if docker is unavailable.
lab-test:
	pytest tests/lab/ -q -s

# Bash regression tests (pipeline, gates, scope, deepthink, skip logging).
bash-test:
	@for t in scripts/tests/*.sh; do echo "== $$t"; bash "$$t" || exit 1; done
