# An agent in an OpenShell sandbox on Kubernetes, on the mesh under its own
# identity. Nothing in OpenShell is modified: the Helm chart is installed as
# published with one value set, and the integration is one provider profile.
#
#   make cluster                 kind cluster (skip on a cluster you already have)
#   make prereqs                 Agent Sandbox controller, SPIRE (server, agent, CSI, OIDC)
#   make mesh                    the mesh: hub (HUB=local) or join HUB=<url>, edge + office nodes
#   make openshell               OpenShell gateway via Helm, CLI registration, the provider
#   make up                      prereqs + mesh + openshell
#   make sandbox NAME=demo       create a sandbox with the provider; prints its SPIFFE ID
#   make bind NAME=demo          add that sandbox's identity to the sandbox role and push
#   make unbind NAME=demo        remove it again (revocation is a policy change)
#   make call NAME=demo          from inside the sandbox: tools, calc allowed, payroll refused
#   make rogue                   a sandbox the policy does not bind: refused
#   make netpol-check            prove the CNI enforces NetworkPolicy (workload cannot bypass the supervisor)
#   make policy                  push policy.json to the hub
#   make down                    remove sandboxes, OpenShell, the mesh, SPIRE
#
# Needs: kubectl, helm, docker (to build the sandbox image), the openshell CLI
# (0.1.4 or later), python3, curl. KUBE_CONTEXT selects the cluster. For kind,
# `make cluster` creates it and loads images; on GKE set
# OIDC_SERVICE_TYPE=LoadBalancer so the hub on Cloud Run can reach SPIRE's
# issuer, and HUB to the Cloud Run URL.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

NAME ?= demo
# Local port for the port-forward to the OpenShell gateway.
GATEWAY_PORT ?= 18080
KIND_CLUSTER_NAME ?= openshell
KUBE_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)
K := kubectl --context $(KUBE_CONTEXT)
H := helm --kube-context $(KUBE_CONTEXT)
CLUSTER_NAME ?= $(KIND_CLUSTER_NAME)
TRUST_DOMAIN := openshell.local

AGENT_SANDBOX_VERSION ?= v1.0.7
SPIRE_CRDS_VERSION ?= 0.5.0
SPIRE_CHART_VERSION ?= 0.29.0
OPENSHELL_VERSION ?= 0.1.4
# Name of this cluster's gateway in the openshell CLI; use one name per cluster.
OPENSHELL_GATEWAY ?= openshell-k8s
AGENTMESH_VERSION ?= v0.1.1
AGENTMESH_ONE_IMAGE ?= ghcr.io/google/agentmesh-one:$(AGENTMESH_VERSION)
AGENTMESH_NODE_IMAGE ?= ghcr.io/google/agentmesh-node:$(AGENTMESH_VERSION)
CALC_MCP_IMAGE ?= calc-mcp:local
SANDBOX_IMAGE ?= openshell-agentmesh-sandbox:local

# HUB=local runs agentmesh-one in the cluster; HUB=https://... joins one that
# already runs elsewhere (Cloud Run). The admin token for a remote hub comes
# from run/admin-token (write it there); the join token from run/join-token.
HUB ?= local
ifeq ($(HUB),local)
CONTROL_PLANE_URL := http://agentmesh-one.agentmesh.svc.cluster.local:8080
CONTROL_PLANE_INSECURE_ARG := - --insecure-control-plane
HUB_URL_LOCAL := http://127.0.0.1:18070
else
CONTROL_PLANE_URL := $(HUB)
CONTROL_PLANE_INSECURE_ARG :=
HUB_URL_LOCAL := $(HUB)
endif

# The issuer SPIRE's OIDC discovery provider names in every JWT-SVID and the
# control plane fetches keys from. In-cluster by default; on GKE a LoadBalancer
# Service and JWT_ISSUER=http://<ip> so the hub on Cloud Run can reach it.
OIDC_SERVICE_TYPE ?= ClusterIP
OIDC_LOAD_BALANCER_IP ?=
JWT_ISSUER ?= http://spire-spiffe-oidc-discovery-provider.spire.svc.cluster.local

export KIND_CLUSTER_NAME KUBE_CONTEXT

.PHONY: cluster prereqs mesh openshell up sandbox bind unbind call rogue gemini netpol-check policy status down clean

cluster:
	kind get clusters 2>/dev/null | grep -qx "$(KIND_CLUSTER_NAME)" || kind create cluster --name $(KIND_CLUSTER_NAME) --wait 120s

prereqs:
	$(K) apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$(AGENT_SANDBOX_VERSION)/sandbox.yaml
	$(K) -n agent-sandbox-system rollout status deployment --timeout=120s
	helm repo add spire https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1 || true
	helm repo update spire >/dev/null
	$(H) upgrade --install spire-crds spire/spire-crds --version $(SPIRE_CRDS_VERSION) -n spire --create-namespace --wait
	$(K) get namespace openshell >/dev/null 2>&1 || $(K) create namespace openshell
	mkdir -p run
	CLUSTER_NAME="$(CLUSTER_NAME)" JWT_ISSUER="$(JWT_ISSUER)" OIDC_SERVICE_TYPE="$(OIDC_SERVICE_TYPE)" OIDC_LOAD_BALANCER_IP="$(OIDC_LOAD_BALANCER_IP)" \
	  envsubst '$$CLUSTER_NAME $$JWT_ISSUER $$OIDC_SERVICE_TYPE $$OIDC_LOAD_BALANCER_IP' < spire/values.yaml.tmpl > run/spire-values.yaml
	$(H) upgrade --install spire spire/spire --version $(SPIRE_CHART_VERSION) -n spire -f run/spire-values.yaml --wait --timeout 5m
	@echo "SPIRE issuer: $(JWT_ISSUER)"

mesh: run/join-token run/admin-token run/api-token
	$(K) get namespace agentmesh >/dev/null 2>&1 || $(K) create namespace agentmesh
	$(K) -n agentmesh get secret agentmesh-tokens >/dev/null 2>&1 || \
	  $(K) -n agentmesh create secret generic agentmesh-tokens \
	    --from-file=join-token=run/join-token --from-file=admin-token=run/admin-token --from-file=api-token=run/api-token
	if [ "$(HUB)" = local ]; then
	  POLICY_JSON_INDENTED="$$(sed 's/^/    /' policy.json)" AGENTMESH_ONE_IMAGE="$(AGENTMESH_ONE_IMAGE)" JWT_ISSUER="$(JWT_ISSUER)" \
	    envsubst '$$POLICY_JSON_INDENTED $$AGENTMESH_ONE_IMAGE $$JWT_ISSUER' < mesh/hub.yaml.tmpl | $(K) apply -f -
	fi
	calc="$(CALC_MCP_IMAGE)"
	if [ "$$calc" = calc-mcp:local ]; then
	  docker build -q -t calc-mcp:local ../calc-mcp >/dev/null
	  kind load docker-image calc-mcp:local --name $(KIND_CLUSTER_NAME) >/dev/null
	  calc=docker.io/library/calc-mcp:local
	fi
	AGENTMESH_NODE_IMAGE="$(AGENTMESH_NODE_IMAGE)" CALC_MCP_IMAGE="$$calc" CONTROL_PLANE_URL="$(CONTROL_PLANE_URL)" CONTROL_PLANE_INSECURE_ARG="$(CONTROL_PLANE_INSECURE_ARG)" \
	  envsubst '$$AGENTMESH_NODE_IMAGE $$CALC_MCP_IMAGE $$CONTROL_PLANE_URL $$CONTROL_PLANE_INSECURE_ARG' < mesh/nodes.yaml.tmpl | $(K) apply -f -
	$(K) -n agentmesh rollout status deployment --timeout=180s
	@echo "mesh is up; edge node for the sandboxes: http://edge-node.agentmesh.svc.cluster.local:8080"

openshell:
	@command -v openshell >/dev/null || { echo "openshell CLI not found: https://docs.openshell.ai/about/installation"; exit 1; }
	$(H) upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version $(OPENSHELL_VERSION) \
	  -n openshell --create-namespace -f openshell/values.yaml --wait --timeout 5m
	# The chart's client mTLS bundle is the CLI's transport credential over a
	# port-forward; the server certificate names 127.0.0.1.
	mkdir -p run/mtls
	for f in ca.crt tls.crt tls.key; do
	  $(K) -n openshell get secret openshell-client-tls -o jsonpath="{.data.$${f//./\\.}}" | base64 -d > run/mtls/$$f
	done
	mkdir -p ~/.config/openshell/gateways/$(OPENSHELL_GATEWAY)/mtls && cp run/mtls/* ~/.config/openshell/gateways/$(OPENSHELL_GATEWAY)/mtls/
	EDGE_NODE_IP=$$($(K) -n agentmesh get svc edge-node -o jsonpath='{.spec.clusterIP}') \
	  envsubst '$$EDGE_NODE_IP' < openshell/provider-profile.yaml.tmpl > run/provider-profile.yaml
	$(MAKE) --no-print-directory _with-gateway-port-forward CMD='\
	  openshell gateway list 2>/dev/null | grep -qw "$(OPENSHELL_GATEWAY)" || openshell gateway add https://127.0.0.1:$(GATEWAY_PORT) --local --name $(OPENSHELL_GATEWAY); \
	  openshell gateway select $(OPENSHELL_GATEWAY) >/dev/null; \
	  ./profile-apply.sh run/provider-profile.yaml; \
	  openshell provider list 2>/dev/null | grep -qw "agentmesh" || openshell provider create --name agentmesh --type agentmesh --runtime-credentials'
	if [ "$(SANDBOX_IMAGE)" = openshell-agentmesh-sandbox:local ]; then
	  docker build -q -t $(SANDBOX_IMAGE) -f Dockerfile.sandbox . >/dev/null
	  kind load docker-image $(SANDBOX_IMAGE) --name $(KIND_CLUSTER_NAME) >/dev/null
	fi
	@echo "OpenShell $(OPENSHELL_VERSION) is up as gateway '$(OPENSHELL_GATEWAY)'; next: make sandbox NAME=demo"

up: prereqs mesh openshell

# The sandbox's identity on Kubernetes is derived from the sandbox id OpenShell
# puts on the supervisor pod, so it is known only after creation. `bind` adds
# it to the mesh policy.
sandbox:
	$(MAKE) --no-print-directory _with-gateway-port-forward CMD='\
	  openshell sandbox list 2>/dev/null | grep -qw "$(NAME)" || \
	    openshell sandbox create --name $(NAME) --from $(SANDBOX_IMAGE) --provider agentmesh --detach -- sleep infinity'
	id=$$($(MAKE) --no-print-directory _with-gateway-port-forward CMD='openshell sandbox get $(NAME)' | awk '/^ *Id:/ {print $$2}' | head -1)
	test -n "$$id" || { echo "could not read the id of sandbox $(NAME)"; exit 1; }
	echo "$$id" > run/sandbox-id.$(NAME)
	@echo "sandbox $(NAME) is spiffe://$(TRUST_DOMAIN)/openshell/sandbox/$$id; next: make bind NAME=$(NAME) && make call NAME=$(NAME)"

bind:
	python3 bind.py "user:spiffe://$(TRUST_DOMAIN)/openshell/sandbox/$$(cat run/sandbox-id.$(NAME))"
	$(MAKE) --no-print-directory policy

unbind:
	python3 bind.py --remove "user:spiffe://$(TRUST_DOMAIN)/openshell/sandbox/$$(cat run/sandbox-id.$(NAME))"
	$(MAKE) --no-print-directory policy

call:
	$(MAKE) --no-print-directory _with-gateway-port-forward CMD='\
	  echo "== tools the mesh offers sandbox $(NAME)"; python3 mcp.py tools $(NAME); \
	  echo "== mcp://calc, allowed for the sandbox role"; python3 mcp.py add $(NAME) calc 2 3; \
	  echo "== mcp://payroll, not in the sandbox role"; python3 mcp.py add $(NAME) payroll 2 3 || true'

# gemini calls Gemini on Vertex AI from inside the sandbox through the mesh:
# the request goes to the edge node, which forwards it to the office node that
# serves egress://aiplatform.googleapis.com; that node authorizes the method
# and path, mints a federated Google token and injects it. The sandbox holds
# no Google credential. The policy must carry the egress destination and the
# http grant (see the guide); GCP_PROJECT is the project of the destination.
GCP_PROJECT ?=
GCP_REGION ?= us-central1
GEMINI_MODEL ?= gemini-2.5-flash
# AGENT_ENGINE=<reasoning engine id> adds a query to an agent deployed on
# Agent Engine, the same host under another granted path.
AGENT_ENGINE ?=
gemini:
	@test -n "$(GCP_PROJECT)" || { echo "set GCP_PROJECT=<project that hosts the Vertex AI endpoint>"; exit 1; }
	peer="$(PEER)"
	if [ -z "$$peer" ]; then
	  peer=$$($(K) -n agentmesh logs deploy/office-node | grep -o 'PeerID: 12D3Koo[A-Za-z0-9]*' | head -1 | cut -d' ' -f2)
	fi
	base="http://edge-node.agentmesh.svc.cluster.local:8080/mesh/$$peer/egress/aiplatform.googleapis.com/v1/projects/$(GCP_PROJECT)/locations/$(GCP_REGION)"
	$(MAKE) --no-print-directory _with-gateway-port-forward CMD="\
	  echo '== POST $(GEMINI_MODEL):generateContent, granted to the sandbox role'; \
	  openshell sandbox exec --name $(NAME) --no-tty -- curl -sS --max-time 60 -H 'Content-Type: application/json' \
	    -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Answer with one word: what is 2+3?\"}]}]}' \
	    $$base/publishers/google/models/$(GEMINI_MODEL):generateContent \
	    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(\"  answer:\", d[\"candidates\"][0][\"content\"][\"parts\"][0][\"text\"].strip()) if \"candidates\" in d else print(\"  refused:\", d)'; \
	  echo '== GET on the model, a method the grant does not list'; \
	  openshell sandbox exec --name $(NAME) --no-tty -- curl -sS -o /dev/null -w '  HTTP %{http_code} %header{Proxy-Status}\n' $$base/publishers/google/models/$(GEMINI_MODEL); \
	  echo '== POST to another Vertex AI path, outside the granted paths'; \
	  openshell sandbox exec --name $(NAME) --no-tty -- curl -sS -o /dev/null -w '  HTTP %{http_code} %header{Proxy-Status}\n' -X POST -d '{}' $$base/endpoints; \
	  if [ -n '$(AGENT_ENGINE)' ]; then \
	    echo '== POST reasoningEngines/$(AGENT_ENGINE):query, an agent on Agent Engine'; \
	    openshell sandbox exec --name $(NAME) --no-tty -- curl -sS --max-time 60 -H 'Content-Type: application/json' \
	      -d '{\"input\":{\"a\":40,\"b\":2}}' $$base/reasoningEngines/$(AGENT_ENGINE):query \
	      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(\"  output:\", json.dumps(d.get(\"output\", d)))'; \
	  fi"

rogue:
	$(MAKE) --no-print-directory sandbox NAME=rogue
	@echo "== rogue has a SPIFFE ID but the mesh policy binds it to no role"
	$(MAKE) --no-print-directory call NAME=rogue || true
	@echo "== to let it in: make bind NAME=rogue"

# OpenShell's guarantee that the supervisor is the only way out depends on the
# CNI enforcing the NetworkPolicy it creates. From the workload pod, a direct
# connection to the edge node must fail; through the supervisor it works.
netpol-check:
	id=$$(cat run/sandbox-id.$(NAME))
	workload=$$($(K) -n openshell get pods -l openshell.ai/boundary-role=workload,openshell.ai/boundary-pair=$$id -o name | head -1)
	test -n "$$workload" || { echo "no workload pod for sandbox $(NAME)"; exit 1; }
	edge=$$($(K) -n agentmesh get svc edge-node -o jsonpath='{.spec.clusterIP}')
	$(K) -n openshell get networkpolicy -o name
	# By IP, so that the result is about the policy and not about DNS, which the
	# policy also denies. kubectl exec runs outside the sandbox runtime's
	# syscall interception, so this is the pod network the CNI sees.
	if $(K) -n openshell exec $$workload -- timeout 5 curl -sS -o /dev/null http://$$edge:8080/healthz 2>/dev/null; then
	  echo "FAIL: $$workload reached the edge node at $$edge directly; the CNI does not enforce NetworkPolicy"; exit 1
	fi
	echo "OK: $$workload cannot reach $$edge:8080 directly (NetworkPolicy enforced)"
	# Control: a pod in the same namespace that OpenShell's policies do not
	# select reaches the same address, so the refusal above is enforcement and
	# not a network outage. The functional proof is `make call`: the same
	# request succeeds when it goes through the supervisor.
	$(K) -n openshell run -q --rm -i --restart=Never netpol-control --image=curlimages/curl:8.10.1 -- \
	  -sS -o /dev/null -m 5 http://$$edge:8080/healthz \
	  || { echo "FAIL: an unconfined pod cannot reach the edge node either; this is a network problem, not enforcement"; exit 1; }
	echo "OK: an unconfined pod in namespace openshell reaches $$edge:8080 (control)"

policy:
	if [ "$(HUB)" = local ]; then
	  $(K) -n agentmesh port-forward svc/agentmesh-one 18070:8080 >/dev/null 2>&1 &
	  pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT; sleep 2
	fi
	admin_token=$$(cat run/admin-token)
	curl -sS -X POST "$(HUB_URL_LOCAL)/policies" \
	  -H "Authorization: Bearer $$admin_token" \
	  -H 'Content-Type: application/json' --data-binary @policy.json
	@echo

status:
	$(K) -n spire get pods
	$(K) -n agentmesh get pods
	$(K) -n openshell get pods,sandboxes.agents.x-k8s.io,networkpolicies
	$(MAKE) --no-print-directory _with-gateway-port-forward CMD='openshell sandbox list'
	$(K) -n spire exec statefulset/spire-server -c spire-server -- /opt/spire/bin/spire-server entry show 2>/dev/null | grep -E "SPIFFE ID|Selector" | head -20

down:
	-$(MAKE) --no-print-directory _with-gateway-port-forward CMD='openshell sandbox delete demo rogue; openshell provider delete agentmesh; openshell profile delete agentmesh' 2>/dev/null
	-openshell gateway remove $(OPENSHELL_GATEWAY) 2>/dev/null
	-$(H) uninstall openshell -n openshell --wait
	-$(K) delete namespace agentmesh --wait=false
	-$(H) uninstall spire -n spire --wait
	rm -rf run

clean:
	kind delete cluster --name $(KIND_CLUSTER_NAME)

# Runs CMD with the OpenShell gateway port-forwarded to 127.0.0.1:18080.
_with-gateway-port-forward:
	@:
	@if (exec 3<>/dev/tcp/127.0.0.1/$(GATEWAY_PORT)) 2>/dev/null; then
	  echo "127.0.0.1:$(GATEWAY_PORT) is in use (a port-forward left from an earlier run?); free it or set GATEWAY_PORT" >&2; exit 1
	fi
	@$(K) -n openshell port-forward svc/openshell $(GATEWAY_PORT):8080 >/dev/null 2>&1 &
	@pf=$$!; trap 'kill $$pf 2>/dev/null' EXIT INT TERM HUP
	@for _ in $$(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/$(GATEWAY_PORT)) 2>/dev/null && break; sleep 0.5; done
	@# The CLI keeps one selected gateway; each target selects its own, so two
	@# clusters (kind and GKE) can be driven from one workstation.
	@openshell gateway select $(OPENSHELL_GATEWAY) >/dev/null 2>&1 || true
	@$(CMD)

run/join-token:
	mkdir -p run && umask 022 && printf 'mesh_tok_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/admin-token:
	mkdir -p run && umask 022 && printf 'mesh_adm_%s' "$$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > $@

run/api-token:
	mkdir -p run && umask 022 && head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > $@
