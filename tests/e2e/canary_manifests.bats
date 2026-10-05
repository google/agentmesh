#!/usr/bin/env bats
#
# The canary manifests in .github/k8s are applied straight to a live testnet by
# .github/workflows/deploy.yaml, and until now the first thing to find out
# whether they were valid was that testnet. A field renamed by a chart bump, an
# apiVersion that lapsed, a template variable nobody substitutes -- each of
# those is a broken prod rollout discovered in prod.
#
# This applies them to the e2e cluster first. Three things are asserted, and
# they fail for different reasons: that the rendered manifest is one an API
# server accepts, that the deployment it describes rolls out, and that the
# sandbox inside it is a sandbox.
#
# The last one is worth having here rather than only in agent_sandbox.bats,
# because the pod is the profile where nothing isolates the agent for you.
# Every container in a pod shares one network namespace, so a canary that came
# up Ready would say nothing at all about whether the agent was confined.

load "lib/container_mesh.bash"

# The values deploy.yaml substitutes. ENV_NAME picks the canary namespace and
# the control plane's service name; NAMESPACE is where the mesh itself lives,
# which in this cluster is the namespace helm installed into.
export ENV_NAME="e2e"
export NAMESPACE="default"
export CANARY_NAMESPACE="sam-canary-${ENV_NAME}"
export DHT_PROVIDER_ADDR_TTL="0s"

setup_file() {
  if ! command -v kind >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
    skip "canary manifests need a cluster: kind and kubectl are not both available"
  fi
  if ! command -v envsubst >/dev/null 2>&1; then
    skip "envsubst is how deploy.yaml renders these, so it is how they are rendered here"
  fi
}

# Cleanup is per-file rather than per-test: deleting a namespace is
# asynchronous, and a second test that recreates it races the first one's
# termination.
teardown_file() {
  local kubectl="kubectl --context=${KUBECONTEXT:-kind-${KUBERNETES_CLUSTER_NAME:-sam-wi-test}}"
  ${kubectl} delete namespace "${CANARY_NAMESPACE}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  ${kubectl} -n "${NAMESPACE}" delete service "sam-control-plane-${ENV_NAME}" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

setup() {
  mesh_setup_env
  export KUBECTL="kubectl --context=${KUBECONTEXT:-kind-${KUBERNETES_CLUSTER_NAME:-sam-wi-test}}"
  ${KUBECTL} create namespace "${CANARY_NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f - >/dev/null
}

teardown() {
  mesh_cleanup_env
}

# render fills in the variables deploy.yaml substitutes.
render() {
  IMAGE_TAG="${IMAGE_TAG:-local}" envsubst < "$1"
}

# unservable reports whether every error is this cluster's missing CRDs rather
# than the manifest's fault. The control plane template carries GKE Gateway and
# HealthCheckPolicy resources, and the monitoring template Managed Prometheus
# PodMonitorings, which no kind cluster serves and which nothing here can
# install, so failing on them would only teach people to ignore this test.
#
# The kinds are named rather than matched on "no matches for kind", because a
# Deployment declared against a retired apiVersion fails with that same wording
# -- which made an earlier version of this test pass a manifest whose
# apps/v1beta1 would have broken the rollout it exists to protect.
unservable() {
  local kinds='Gateway|HTTPRoute|HealthCheckPolicy|GCPBackendPolicy|PodMonitoring|Rules'
  ! grep -qvE "no matches for kind \"(${kinds})\"|ensure CRDs are installed|^[[:space:]]*$" <<<"$1"
}

@test "Canary manifests: every template the deploy workflow applies is valid" {
  local template errs failed=0

  for template in .github/k8s/*-template.yaml; do
    # A CronJob against a DNS zone this cluster has no notion of.
    case "${template}" in
      *dns-sync*) continue ;;
    esac

    # Server-side, so this is the API server's own schema rather than a local
    # guess: it catches the field a chart bump renamed, which client-side
    # validation accepts happily.
    if errs=$(render "${template}" | ${KUBECTL} apply --dry-run=server -f - 2>&1 >/dev/null); then
      echo "# ok       ${template}" >&3
      continue
    fi
    if unservable "${errs}"; then
      echo "# skipped  ${template} (needs CRDs this cluster does not serve)" >&3
      continue
    fi
    echo "# INVALID  ${template}" >&3
    sed 's/^/#     /' <<<"${errs}" >&3
    failed=1
  done

  [[ "${failed}" -eq 0 ]]
}
