# An Agent Substrate actor on the mesh under its own identity.
#
#   make cluster            kind cluster with Substrate; the egress gateway is
#                           pointed at the Agent Mesh credential provider
#   make up                 the mesh and the provider, in namespace agentmesh
#   make actor NAME=demo    one sandbox actor with an egress policy
#   make call NAME=demo     from inside the actor: tools, calc allowed, payroll refused
#   make rogue              an actor the mesh policy does not bind: refused
#   make policy             push the mesh policy after editing manifests/mesh.yaml.tmpl
#   make check              two actors, different grants: assert each reaches only its own tool
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
# KUBE_CONTEXT selects the cluster. The default is the kind cluster `make
# cluster` creates; for a cluster Substrate's own tooling set up (GKE through
# `tools/setup-gcp bootstrap` + `hack/install-ate.sh`), point it there.
KUBE_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)
CTX := $(KUBE_CONTEXT)
KUBECTL := kubectl --context $(CTX)
KATE := kubectl-ate --context $(CTX)
ATESPACE := ate-demo-sandbox
TEMPLATE := sandbox-template
TRUST_DOMAIN := substrate-actor.local
ROUTER_PORT ?= 8000
KO_DOCKER_REPO ?= localhost:5001
# CALC_MCP_IMAGE: a pullable image for the calc MCP server. Empty builds
# ../calc-mcp and loads it into the kind cluster; on any other cluster set it
# to an image the nodes can pull.
CALC_MCP_IMAGE ?=

AGENTMESH_VERSION ?= v0.1.1
AGENTMESH_ONE_IMAGE ?= ghcr.io/google/agentmesh-one:$(AGENTMESH_VERSION)
AGENTMESH_NODE_IMAGE ?= ghcr.io/google/agentmesh-node:$(AGENTMESH_VERSION)

# HUB=local runs agentmesh-one in the cluster; HUB=https://... joins one that
# runs elsewhere (Cloud Run). With a remote hub the provider's issuer must be
# reachable from it: give the provider a persistent key (PROVIDER_KEY_PATH)
# and publish its discovery document and JWKS where ISSUER points (a public
# bucket), see README. run/join-token and run/admin-token hold the hub's
# tokens when HUB is remote.
HUB ?= local
ifeq ($(HUB),local)
CONTROL_PLANE_URL := http://agentmesh-one.agentmesh.svc.cluster.local:8080
CONTROL_PLANE_INSECURE_ARG := - --insecure-control-plane
ISSUER ?= http://credential-provider.agentmesh.svc.cluster.local:8080
else
CONTROL_PLANE_URL := $(HUB)
CONTROL_PLANE_INSECURE_ARG :=
ISSUER ?= $(error ISSUER is required with a remote HUB: the public URL the provider's discovery document is published at)
endif
PROVIDER_KEY_PATH ?=
ifneq ($(PROVIDER_KEY_PATH),)
PROVIDER_KEY_ARGS := - --signing-key-path=/run/agentmesh-provider/p256.pem\n        - --jwks-uri=$(ISSUER)/keys
else
PROVIDER_KEY_ARGS :=
endif

KUBECTL_CONTEXT := $(CTX)
export KIND_CLUSTER_NAME KUBECTL_CONTEXT KO_DOCKER_REPO

.PHONY: cluster up issuer-docs actor call gemini rogue policy check status down clean

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

up: run/join-token run/admin-token run/api-token
	$(KUBECTL) apply -f manifests/namespace.yaml
	$(KUBECTL) -n agentmesh get secret agentmesh-tokens >/dev/null 2>&1 || \
	  $(KUBECTL) -n agentmesh create secret generic agentmesh-tokens \
	    --from-file=join-token=run/join-token --from-file=admin-token=run/admin-token --from-file=api-token=run/api-token
	if [ -n "$(PROVIDER_KEY_PATH)" ]; then
	  $(KUBECTL) -n agentmesh create secret generic credential-provider-signing-key --from-file=p256.pem=$(PROVIDER_KEY_PATH) --dry-run=client -o yaml | $(KUBECTL) apply -f -
	fi
	provider=$$(cd credential-provider && KO_DOCKER_REPO=$(KO_DOCKER_REPO)/agentmesh-credential-provider ko build --platform=linux/$$(go env GOARCH) --bare .)
	calc="$(CALC_MCP_IMAGE)"
	if [ -z "$$calc" ]; then
	  calc=$$(docker build -q ../calc-mcp -t calc-mcp:local >/dev/null && kind load docker-image calc-mcp:local --name $(KIND_CLUSTER_NAME) >/dev/null && echo docker.io/library/calc-mcp:local)
	fi
	if [ "$(HUB)" = local ]; then
	  AGENTMESH_ONE_IMAGE="$(AGENTMESH_ONE_IMAGE)" ISSUER="$(ISSUER)" envsubst '$$AGENTMESH_ONE_IMAGE $$ISSUER' < manifests/hub.yaml.tmpl | $(KUBECTL) apply -f -
	fi
	AGENTMESH_NODE_IMAGE="$(AGENTMESH_NODE_IMAGE)" CALC_MCP_IMAGE="$$calc" CONTROL_PLANE_URL="$(CONTROL_PLANE_URL)" CONTROL_PLANE_INSECURE_ARG="$(CONTROL_PLANE_INSECURE_ARG)" \
	  envsubst '$$AGENTMESH_NODE_IMAGE $$CALC_MCP_IMAGE $$CONTROL_PLANE_URL $$CONTROL_PLANE_INSECURE_ARG' < manifests/mesh.yaml.tmpl | $(KUBECTL) apply -f -
	CREDENTIAL_PROVIDER_IMAGE="$$provider" ISSUER="$(ISSUER)" PROVIDER_KEY_ARGS="$$(printf '%b' '$(PROVIDER_KEY_ARGS)')" \
	  envsubst '$$CREDENTIAL_PROVIDER_IMAGE $$ISSUER $$PROVIDER_KEY_ARGS' < manifests/credential-provider.yaml.tmpl | $(KUBECTL) apply -f -
	$(KUBECTL) -n agentmesh rollout status deployment --timeout=180s
	$(KUBECTL) -n ate-system rollout status deployment/atenet-egress --timeout=120s
	@echo "next: make actor NAME=demo && make call NAME=demo"

# Writes the provider's discovery document and JWKS for PROVIDER_KEY_PATH into
# run/issuer/, to be published at ISSUER (for example
# `gcloud storage cp -r run/issuer/* gs://<bucket>/substrate/`).
issuer-docs:
	@test -n "$(PROVIDER_KEY_PATH)" || { echo "PROVIDER_KEY_PATH is required"; exit 1; }
	rm -rf run/issuer && mkdir -p run/issuer
	cd credential-provider && go run . --print-discovery --print-discovery-dir ../run/issuer --issuer "$(ISSUER)" --jwks-uri "$(ISSUER)/keys" --signing-key-path "$(PROVIDER_KEY_PATH)"
	@find run/issuer -type f

run/join-token:
	mkdir -p run && umask 077 && printf 'mesh_tok_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/admin-token:
	mkdir -p run && umask 077 && printf 'mesh_adm_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/api-token:
	mkdir -p run && umask 077 && head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > $@

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
	if (exec 3<>/dev/tcp/127.0.0.1/$(ROUTER_PORT)) 2>/dev/null; then
	  echo "127.0.0.1:$(ROUTER_PORT) is in use (a port-forward left from an earlier run?); free it or set ROUTER_PORT" >&2; exit 1
	fi
	$(KUBECTL) -n ate-system port-forward service/atenet-router $(ROUTER_PORT):80 >/dev/null 2>&1 &
	pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT INT TERM HUP; sleep 2
	@echo "== tools the mesh offers actor $(NAME)"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py tools $(NAME)
	@echo "== mcp://calc, allowed for the actor role"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py add $(NAME) calc 2 3
	@echo "== mcp://payroll, not in the actor role"
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 mcp.py add $(NAME) payroll 2 3 || true

# gemini calls Gemini on Vertex AI from inside the actor through the mesh (see
# gemini.py). The policy must carry the egress destination and the http grant
# (see the guide); GCP_PROJECT is the project of the destination; PEER is the
# office node that serves it (default: this cluster's).
GCP_PROJECT ?=
GCP_REGION ?= us-central1
GEMINI_MODEL ?= gemini-2.5-flash
# AGENT_ENGINE=<reasoning engine id> adds a query to an agent on Agent Engine.
AGENT_ENGINE ?=
gemini:
	@test -n "$(GCP_PROJECT)" || { echo "set GCP_PROJECT=<project that hosts the Vertex AI endpoint>"; exit 1; }
	peer="$(PEER)"
	if [ -z "$$peer" ]; then
	  peer=$$($(KUBECTL) -n agentmesh logs deploy/office-node | grep -o 'PeerID: 12D3Koo[A-Za-z0-9]*' | head -1 | cut -d' ' -f2)
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/$(ROUTER_PORT)) 2>/dev/null; then
	  echo "127.0.0.1:$(ROUTER_PORT) is in use (a port-forward left from an earlier run?); free it or set ROUTER_PORT" >&2; exit 1
	fi
	$(KUBECTL) -n ate-system port-forward service/atenet-router $(ROUTER_PORT):80 >/dev/null 2>&1 &
	pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT INT TERM HUP; sleep 2
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) python3 gemini.py $(NAME) $$peer $(GCP_PROJECT) $(GCP_REGION) $(GEMINI_MODEL) $(AGENT_ENGINE)

rogue:
	$(MAKE) actor NAME=rogue
	@echo "== rogue has an actor identity but the mesh policy binds it to no role"
	$(MAKE) call NAME=rogue || true
	@echo "== to let it in: add user:spiffe://$(TRUST_DOMAIN)/actor/$(ATESPACE)/rogue to the actor role in manifests/mesh.yaml.tmpl, then make policy"

# Replaces the whole mesh policy. Nodes pick it up within 30s; an actor gets
# its new roles when the provider's cached credential expires (--cache-ttl).
policy:
	if [ "$(HUB)" = local ]; then
	  $(KUBECTL) -n agentmesh port-forward svc/agentmesh-one 18070:8080 >/dev/null 2>&1 &
	  pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT; sleep 2
	  hub=http://127.0.0.1:18070
	else
	  hub=$(HUB)
	fi
	admin_token=$$(cat run/admin-token)
	curl -sS -X POST "$$hub/policies" \
	  -H "Authorization: Bearer $$admin_token" \
	  -H 'Content-Type: application/json' \
	  --data-binary "$$($(KUBECTL) -n agentmesh get configmap mesh-config -o jsonpath='{.data.policy\.json}')"
	@echo

# check asserts the mesh keeps two authorized actors with different grants
# apart: demo (the `actor` role, mcp://calc) and ledger (the `ledger` role,
# mcp://payroll) each reach only their own tool. It pushes the policy first so
# the ledger binding is live, brings both actors up, then restarts the
# credential provider so its in-memory cache is empty and the actors' next
# request is minted under the policy just pushed, without waiting out
# --cache-ttl. The worker pool holds two actors, so a `rogue` left over from
# `make rogue` must be suspended first.
check:
	$(MAKE) policy
	$(MAKE) actor NAME=demo
	$(MAKE) actor NAME=ledger
	$(KUBECTL) -n agentmesh rollout restart deployment/credential-provider
	$(KUBECTL) -n agentmesh rollout status deployment/credential-provider --timeout=90s
	ROUTER_PORT=$(ROUTER_PORT) ATESPACE=$(ATESPACE) KUBE_CONTEXT=$(CTX) ./check.sh

status:
	$(KUBECTL) -n agentmesh get pods
	$(KATE) get actors -a $(ATESPACE)
	$(KUBECTL) -n ate-system logs deployment/atenet-egress -c ext-proc --tail=20 2>/dev/null | grep -iE 'agentmesh|credential|denied' || true

down:
	-for a in demo ledger rogue; do $(KATE) suspend actor $$a -a $(ATESPACE) >/dev/null 2>&1; $(KATE) delete actor $$a -a $(ATESPACE) >/dev/null 2>&1; done
	# The namespace and the credential-provider Service stay: the egress gateway
	# was installed with that Service's address and holds its ClusterIP.
	-$(KUBECTL) -n agentmesh delete deployment,configmap,secret,networkpolicy --all --timeout=120s
	-$(KUBECTL) -n agentmesh delete service edge-node calc-mcp --ignore-not-found

clean:
	kind delete cluster --name $(KIND_CLUSTER_NAME)
