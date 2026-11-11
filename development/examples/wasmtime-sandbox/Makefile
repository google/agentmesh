# An agent in a Wasmtime capability sandbox, on the mesh under its own identity.
#
#   make up                 start the host OIDC issuer, agentmesh-one, office-node, and edge-node
#   make sandbox NAME=demo  show the SPIFFE ID minted for sandbox $(NAME)
#   make call NAME=demo     from inside the Wasm guest: call mcp://calc (allowed) and mcp://payroll (refused)
#   make rogue              a second Wasm sandbox with no role: same guest module, refused
#   make policy             push policy.json to the running mesh after editing it
#   make check              verify role isolation across demo, ledger, and rogue sandboxes
#   make down               stop the background topology and remove run/
#
# Needs: a Rust toolchain (cargo) and curl on this machine. No Docker or
# Kubernetes required; everything listens on 127.0.0.1 only.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

NAME ?= demo
TRUST_DOMAIN := agentmesh.local

.PHONY: up sandbox call rogue policy check status down

up:
	./run.sh build >/dev/null 2>&1 || cargo build --release --quiet
	if [ -f run/supervisor.pid ] && kill -0 "$$(cat run/supervisor.pid)" 2>/dev/null; then
	  echo "Topology is already running (PID $$(cat run/supervisor.pid))."
	  exit 0
	fi
	mkdir -p run
	nohup ./run.sh serve > run/supervisor.log 2>&1 &
	echo $$! > run/supervisor.pid
	for _ in $$(seq 1 60); do
	  [ -s run/ports.env ] && grep -q '^ONE_API_PORT=' run/ports.env && break
	  kill -0 "$$(cat run/supervisor.pid)" 2>/dev/null || { cat run/supervisor.log >&2; exit 1; }
	  sleep 0.5
	done
	. run/ports.env
	@echo "Mesh console:  http://127.0.0.1:$${ONE_API_PORT}/console/  (admin token in run/admin-token)"
	@echo "Next:          make call NAME=demo"

sandbox:
	@echo "sandbox $(NAME) runs with workload identity spiffe://$(TRUST_DOMAIN)/wasm/$(NAME)/epoch/0; try: make call NAME=$(NAME)"

call:
	./run.sh call --name $(NAME)

rogue:
	@echo "== rogue has a SPIFFE ID (spiffe://$(TRUST_DOMAIN)/wasm/rogue/epoch/0) but policy.json binds it to no role"
	./run.sh call --name rogue || true
	@echo "== to let it in: add user:spiffe://$(TRUST_DOMAIN)/wasm/rogue/epoch/* to the sandbox role in policy.json, then make policy"

policy:
	. run/ports.env
	curl -sS -X POST "http://127.0.0.1:$${ONE_API_PORT}/policies" \
	  -H "Authorization: Bearer $$(cat run/admin-token)" \
	  -H 'Content-Type: application/json' --data-binary @policy.json
	@echo

check:
	if [ -f run/ports.env ] && [ -f run/supervisor.pid ] && kill -0 "$$(cat run/supervisor.pid)" 2>/dev/null; then
	  ./check.sh
	else
	  ./run.sh check
	fi

status:
	if [ -f run/supervisor.pid ] && kill -0 "$$(cat run/supervisor.pid)" 2>/dev/null; then
	  echo "supervisor running (PID $$(cat run/supervisor.pid))"
	  cat run/ports.env
	else
	  echo "supervisor is not running"
	fi

down:
	if [ -f run/supervisor.pid ]; then
	  kill "$$(cat run/supervisor.pid)" 2>/dev/null || true
	  wait "$$(cat run/supervisor.pid)" 2>/dev/null || true
	fi
	rm -rf run
