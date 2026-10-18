# An agent in an OpenShell sandbox, on the mesh under its own identity.
#
#   make up                 SPIRE, the mesh, the OpenShell gateway; register the provider
#   make sandbox NAME=demo  give one sandbox a SPIFFE ID, then create it with the provider
#   make call NAME=demo     from inside the sandbox: list tools, add 2+3 on calc, try payroll
#   make rogue              a second sandbox with no role: same image, same profile, refused
#   make policy             push policy.json to the running mesh after editing it
#   make down               remove the sandboxes and everything `up` created
#
# Needs: docker with the compose plugin, the openshell CLI (0.1.3 or later),
# python3 and curl on this machine. Everything listens on 127.0.0.1 only.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

NAME ?= demo
GATEWAY ?= openshell-agentmesh
TRUST_DOMAIN := openshell.local
SPIRE := docker compose exec -T --interactive=false spire-server /opt/spire/bin/spire-server
SANDBOX_IMAGE := openshell-agentmesh-sandbox:local

.PHONY: up sandbox call rogue policy status down select-gateway

up: run/join-token run/api-token run/admin-token
	@command -v openshell >/dev/null || { echo "openshell CLI not found: https://docs.openshell.ai/about/installation"; exit 1; }
	docker compose up -d spire-server spire-oidc
	@for _ in $$(seq 1 30); do $(SPIRE) healthcheck >/dev/null 2>&1 && break; sleep 1; done
	$(SPIRE) healthcheck
	# One join token admits the agent as spiffe://$(TRUST_DOMAIN)/host, the
	# parent of every sandbox entry.
	if [ ! -s run/agent.conf ]; then
	  token=$$($(SPIRE) token generate -spiffeID spiffe://$(TRUST_DOMAIN)/host | awk '/^Token:/ {print $$2}')
	  test -n "$$token"
	  umask 022 && sed "s|\$${SPIRE_JOIN_TOKEN}|$$token|" spire/agent.conf.in > run/agent.conf
	fi
	docker build -q -t $(SANDBOX_IMAGE) sandbox >/dev/null
	docker compose up -d --build
	@for _ in $$(seq 1 60); do curl -sf http://127.0.0.1:8085/healthz >/dev/null && break; sleep 1; done
	curl -sf http://127.0.0.1:8085/healthz >/dev/null
	openshell gateway list 2>/dev/null | grep -q '^$(GATEWAY)\b' || openshell gateway add http://127.0.0.1:8080 --name $(GATEWAY)
	openshell gateway select $(GATEWAY) >/dev/null
	openshell profile import -f openshell/provider-profile.yaml
	openshell provider list 2>/dev/null | grep -q '^agentmesh\b' || openshell provider create --name agentmesh --type agentmesh --runtime-credentials
	@echo
	@echo "Mesh console:  http://127.0.0.1:8070/console/  (admin token in run/admin-token)"
	@echo "Next:          make sandbox NAME=demo && make call NAME=demo"

# The sandbox's identity is a SPIRE registration entry keyed on the label
# OpenShell puts on the sandbox's supervisor container. The mesh policy
# (policy.json) says what that identity may call.
# The CLI keeps one selected gateway; the targets that talk to this one
# select it, so another cluster's gateway on the same workstation does not
# receive the commands.
sandbox: select-gateway
	entry=$$($(SPIRE) entry show -spiffeID spiffe://$(TRUST_DOMAIN)/sandbox/$(NAME) | awk '/^Entry ID/ {print $$4}')
	if [ -z "$$entry" ]; then
	  entry=$$($(SPIRE) entry create \
	    -parentID spiffe://$(TRUST_DOMAIN)/host \
	    -spiffeID spiffe://$(TRUST_DOMAIN)/sandbox/$(NAME) \
	    -selector docker:label:openshell.ai/sandbox-name:$(NAME) | awk '/^Entry ID/ {print $$4}')
	fi
	test -n "$$entry"
	# The agent learns about the entry on its next sync and mints the SVID.
	for _ in $$(seq 1 30); do
	  docker compose logs --no-log-prefix spire-agent 2>/dev/null | grep -q "entry_id=$$entry " && break
	  sleep 1
	done
	openshell sandbox create --name $(NAME) --from $(SANDBOX_IMAGE) --provider agentmesh --detach -- sleep infinity
	@echo "sandbox $(NAME) is spiffe://$(TRUST_DOMAIN)/sandbox/$(NAME) (SPIRE entry $$entry); try: make call NAME=$(NAME)"

call: select-gateway
	@echo "== tools the mesh offers sandbox $(NAME)"
	python3 mcp.py tools $(NAME)
	@echo "== mcp://calc, allowed for the sandbox role"
	python3 mcp.py add $(NAME) calc 2 3
	@echo "== mcp://payroll, not in the sandbox role"
	python3 mcp.py add $(NAME) payroll 2 3 || true

rogue:
	$(MAKE) sandbox NAME=rogue
	@echo "== rogue has a SPIFFE ID but policy.json binds it to no role"
	$(MAKE) call NAME=rogue || true
	@echo "== to let it in: add user:spiffe://$(TRUST_DOMAIN)/sandbox/rogue to the sandbox role in policy.json, then make policy"

# Replaces the whole mesh policy. Nodes pick it up within their sync interval;
# a sandbox gets the new roles when the OpenShell supervisor next renews its
# cached credential (cache_ttl_seconds in the provider profile).
policy:
	curl -sS -X POST http://127.0.0.1:8070/policies \
	  -H "Authorization: Bearer $$(cat run/admin-token)" \
	  -H 'Content-Type: application/json' --data-binary @policy.json
	@echo

status:
	docker compose ps
	openshell sandbox list
	$(SPIRE) entry show

down:
	-openshell sandbox delete demo rogue 2>/dev/null
	-openshell provider delete agentmesh 2>/dev/null
	-openshell profile delete agentmesh 2>/dev/null
	-openshell gateway remove $(GATEWAY) 2>/dev/null
	docker compose down -v --remove-orphans
	rm -rf run
	@echo "left in place: /var/lib/openshell (OpenShell state and the SPIRE agent socket directory)"

run/join-token:
	mkdir -p run && umask 022 && printf 'mesh_tok_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/admin-token:
	mkdir -p run && umask 022 && printf 'mesh_adm_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/api-token:
	mkdir -p run && umask 022 && head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > $@

select-gateway:
	@openshell gateway select $(GATEWAY) >/dev/null
