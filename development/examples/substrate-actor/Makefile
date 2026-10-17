# An Agent Substrate actor on the mesh under its own identity.
#
#   make cluster            kind cluster with Substrate; the egress gateway is
#                           pointed at the Agent Mesh credential provider
#   make up                 the mesh and the provider, in namespace agentmesh
#   make actor NAME=demo    one sandbox actor with an egress policy
#   make call NAME=demo     from inside the actor: tools, calc allowed, payroll refused
#   make rogue              an actor the mesh policy does not bind: refused
#   make policy             push the mesh policy after editing manifests/mesh.yaml.tmpl
#   make down               remove the actors, the mesh and the provider
#   make clean              delete the kind cluster
#
# Needs: docker, kind, ko, kubectl, go, python3, and a checkout of Agent
# Substrate in SUBSTRATE_DIR (default ../../../../substrate). `make cluster`
# builds Substrate from that checkout, which takes a while the first time.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

NAME ?= demo
SUBSTRATE_DIR ?= $(abspath ../../../../substrate)
KIND_CLUSTER_NAME ?= kind
CTX := kind-$(KIND_CLUSTER_NAME)
KUBECTL := kubectl --context $(CTX)
KATE := kubectl-ate --context $(CTX)
ATESPACE := ate-demo-sandbox
TEMPLATE := sandbox-template
TRUST_DOMAIN := substrate-actor.local
ROUTER_PORT ?= 8000
KO_DOCKER_REPO ?= localhost:5001

AGENTMESH_VERSION ?= latest
AGENTMESH_ONE_IMAGE ?= ghcr.io/google/agentmesh-one:$(AGENTMESH_VERSION)
AGENTMESH_NODE_IMAGE ?= ghcr.io/google/agentmesh-node:$(AGENTMESH_VERSION)

KUBECTL_CONTEXT := $(CTX)
export KIND_CLUSTER_NAME KUBECTL_CONTEXT KO_DOCKER_REPO

.PHONY: cluster up actor call rogue policy status down clean

cluster:
	@for t in docker kind ko kubectl go python3; do command -v $$t >/dev/null || { echo "$$t not found"; exit 1; }; done
	@test -f "$(SUBSTRATE_DIR)/hack/install-ate-kind.sh" || { echo "SUBSTRATE_DIR=$(SUBSTRATE_DIR) is not an Agent Substrate checkout"; exit 1; }
	kind get clusters 2>/dev/null | grep -qx "$(KIND_CLUSTER_NAME)" || (cd "$(SUBSTRATE_DIR)" && ./hack/create-kind-cluster.sh)
	# The provider's Service must resolve when the gateway starts, so the
	# namespace and Service exist before Substrate does; the pods come with `make up`.
	$(KUBECTL) apply -f manifests/namespace.yaml
	cd "$(SUBSTRATE_DIR)" && ./hack/install-ate-kind.sh --deploy-ate-system --deploy-demo-sandbox \
	  --credential-provider='{"name":"agentmesh","address":"credential-provider.agentmesh.svc:50051"}'
	cd "$(SUBSTRATE_DIR)" && go install ./cmd/kubectl-ate
	@echo "Substrate is up; next: make up"

up:
	$(KUBECTL) apply -f manifests/namespace.yaml
	$(KUBECTL) -n agentmesh get secret agentmesh-tokens >/dev/null 2>&1 || \
	  $(KUBECTL) -n agentmesh create secret generic agentmesh-tokens \
	    --from-literal=join-token="mesh_tok_$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
	    --from-literal=admin-token="mesh_adm_$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
	    --from-literal=api-token="$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
	provider=$$(cd credential-provider && KO_DOCKER_REPO=$(KO_DOCKER_REPO)/agentmesh-credential-provider ko build --platform=linux/$$(go env GOARCH) --bare .)
	calc=$$(docker build -q ../calc-mcp -t calc-mcp:local >/dev/null && kind load docker-image calc-mcp:local --name $(KIND_CLUSTER_NAME) >/dev/null && echo docker.io/library/calc-mcp:local)
	for f in manifests/mesh.yaml.tmpl manifests/credential-provider.yaml.tmpl; do
	  AGENTMESH_ONE_IMAGE="$(AGENTMESH_ONE_IMAGE)" AGENTMESH_NODE_IMAGE="$(AGENTMESH_NODE_IMAGE)" \
	  CREDENTIAL_PROVIDER_IMAGE="$$provider" CALC_MCP_IMAGE="$$calc" \
	  envsubst '$$AGENTMESH_ONE_IMAGE $$AGENTMESH_NODE_IMAGE $$CREDENTIAL_PROVIDER_IMAGE $$CALC_MCP_IMAGE' < $$f | $(KUBECTL) apply -f -
	done
	$(KUBECTL) -n agentmesh rollout status deployment --timeout=180s
	$(KUBECTL) -n ate-system rollout status deployment/atenet-egress --timeout=120s
	@echo "mesh console: kubectl -n agentmesh port-forward svc/agentmesh-one 8070:8080  ->  http://127.0.0.1:8070/console/"
	@echo "next: make actor NAME=demo && make call NAME=demo"

# The actor's identity is spiffe://$(TRUST_DOMAIN)/actor/$(ATESPACE)/<name>,
# which Substrate derives from the certificate it gives the actor. The mesh
# policy in manifests/mesh.yaml.tmpl says what that identity may call.
actor:
	$(KATE) create actor $(NAME) -a $(ATESPACE) --template $(TEMPLATE) 2>&1 | grep -v AlreadyExists || true
	$(KATE) create egress-policy $(NAME) -a $(ATESPACE) -f egress-policy.yaml 2>&1 | grep -vE 'AlreadyExists|^ATESPACE|^$(ATESPACE) ' || true
	# Resume is asynchronous and the first attempt can land before a worker
	# is free; ask again until the actor reports RUNNING.
	for _ in $$(seq 1 40); do
	  $(KATE) get actors -a $(ATESPACE) 2>/dev/null | grep "^$(ATESPACE) *$(NAME) " | grep -q ACTOR_STATE_RUNNING && break
	  $(KATE) resume actor $(NAME) -a $(ATESPACE) >/dev/null 2>&1 || true
	  sleep 3
	done
	$(KATE) get actors -a $(ATESPACE) | grep "^$(ATESPACE) *$(NAME) " | grep -q ACTOR_STATE_RUNNING || { echo "actor $(NAME) did not reach RUNNING"; exit 1; }
	@echo "actor $(NAME) is spiffe://$(TRUST_DOMAIN)/actor/$(ATESPACE)/$(NAME); try: make call NAME=$(NAME)"

call:
	$(KUBECTL) -n ate-system port-forward service/atenet-router $(ROUTER_PORT):80 >/dev/null 2>&1 &
	pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT; sleep 2
	@echo "== tools the mesh offers actor $(NAME)"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py tools $(NAME)
	@echo "== mcp://calc, allowed for the actor role"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py add $(NAME) calc 2 3
	@echo "== mcp://payroll, not in the actor role"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py add $(NAME) payroll 2 3 || true

rogue:
	$(MAKE) actor NAME=rogue
	@echo "== rogue has an actor identity but the mesh policy binds it to no role"
	$(MAKE) call NAME=rogue || true
	@echo "== to let it in: add user:spiffe://$(TRUST_DOMAIN)/actor/$(ATESPACE)/rogue to the actor role in manifests/mesh.yaml.tmpl, then make policy"

# Replaces the whole mesh policy. Nodes pick it up within 30s; an actor gets
# its new roles when the provider's cached credential expires (--cache-ttl).
policy:
	$(KUBECTL) -n agentmesh port-forward svc/agentmesh-one 18070:8080 >/dev/null 2>&1 &
	pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT; sleep 2
	curl -sS -X POST http://127.0.0.1:18070/policies \
	  -H "Authorization: Bearer $$($(KUBECTL) -n agentmesh get secret agentmesh-tokens -o jsonpath='{.data.admin-token}' | base64 -d)" \
	  -H 'Content-Type: application/json' \
	  --data-binary "$$($(KUBECTL) -n agentmesh get configmap mesh-config -o jsonpath='{.data.policy\.json}')"
	@echo

status:
	$(KUBECTL) -n agentmesh get pods
	$(KATE) get actors -a $(ATESPACE)
	$(KUBECTL) -n ate-system logs deployment/atenet-egress -c ext-proc --tail=20 2>/dev/null | grep -iE 'agentmesh|credential|denied' || true

down:
	-for a in demo rogue; do $(KATE) suspend actor $$a -a $(ATESPACE) >/dev/null 2>&1; $(KATE) delete actor $$a -a $(ATESPACE) >/dev/null 2>&1; done
	-$(KUBECTL) delete namespace agentmesh --wait=false

clean:
	kind delete cluster --name $(KIND_CLUSTER_NAME)
