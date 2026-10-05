---
title: "Contributing"
linkTitle: "Contributing"
weight: 7
aliases:
  - /docs/development/
  - /docs/development/testing/
  - /docs/development/kubernetes-deployment/
---

How to build SAM from source, run its tests, and bring up a local mesh to
develop against. Contributions go through GitHub pull requests and need a
signed [Contributor License Agreement](https://cla.developers.google.com/).
[CONTRIBUTING.md](https://github.com/google/sam/blob/main/CONTRIBUTING.md)
in the repository has the details.

## Layout

| Path | Contents |
|---|---|
| `cmd/` | One directory per binary: `sam-node`, `sam-control-plane`, `sam-router`, `sam-one`, `sam-console`, `mcp-client`, `sam-bench`, and smaller tools. |
| `api/` | The wire contract: `sam.proto` and its generated code, plus the Go types for the JSON admin API and the validation and Datalog helpers both sides share. |
| `internal/` | Implementation, one package per component (`node`, `controlplane`, `router`, `standalone`, `console`, `identity`, `storage`, ...). |
| `charts/` | The `sam-mesh` and `sam-node` Helm charts. |
| `tests/integration/` | Go tests that start several components in one process. |
| `tests/e2e/` | Bats tests that drive the built binaries and containers. |
| `development/` | The kind environment and example services. |
| `site/` | This documentation, a Hugo site. |

Two rules from `AGENTS.md` shape most changes. Components talk to each other
only through `api/sam.proto` (protobuf for anything a mesh component speaks,
protojson of the same messages for the operator API). And no new module may be
added to `go.mod` without discussion. Conformance harnesses with external gRPC
dependencies such as `tests/extproc/` live in their own module for that reason.

## Build

You need Go 1.25 or later. Docker is needed for the container tests and the
linter, and `bats-core` for the end-to-end tests.

```bash
git clone https://github.com/google/sam.git && cd sam
make build        # binaries in ./bin
make docker-build # container images tagged :local
make proto        # regenerate api/sam.pb.go after editing sam.proto
```

The repository has a dev container (`.devcontainer/devcontainer.json`) with
Go, Node, Python and Docker, and `make build` runs when it is created. Open
it in a [GitHub codespace](https://codespaces.new/google/sam?quickstart=1)
or with the VS Code Dev Containers extension to build and test with nothing
installed locally. `make testnet` inside a codespace starts `sam-one` on the
codespace's public URL, so you can point an SDK program or a phone at your
branch; the [Codespaces guide](../guides/codespaces/) has the steps.

Node and router control-plane requests identify themselves as
`sam-node/<version>` and `sam-router/<version>`, including the router inside
`sam-one`. These headers contain the software component and build version.
They are diagnostic metadata that a caller can spoof and are never used for
authentication or authorization. They do not include peer IDs, credentials,
or authorization roles. Publishing a version lets an observer identify the
software release; keeping dependencies patched remains necessary.

`make` derives the version from `git describe --tags --always --dirty`.
You can override it with `make build VERSION=v0.1.0-custom` and inspect the
node binary with `bin/sam-node --version`. Release binaries use the release
tag, and published node, router and `sam-one` images use the tag or commit
SHA. For direct Docker builds of those images, pass `--build-arg VERSION=...`;
without it, the version is `devel`. Plain `go build` uses Go's embedded module
or VCS metadata when available and falls back to `devel`.

## Test

The suite is layered so that most coverage lives where it runs fastest.

| Command | What runs | Time |
|---|---|---|
| `make test` | Every Go test with the race detector: the unit tests next to the code, and the integration tests under `tests/integration/`, which start a control plane, a router and nodes in one process. Each integration test is expected to finish within ten seconds. `WHAT=TestName` runs a subset. | minutes |
| `make e2e-test` | The Bats suite under `tests/e2e/`, in parallel. It covers the CLI (`sam.bats`), a containerised mesh with a mock identity provider (`container_mesh.bats` and the tests built on it), policy, services, A2A, the console, `sam-one`, and the sandbox. It builds the binaries and images first. `WHAT=pattern` filters the tests. | 10 to 30 minutes |
| `make test-e2e-container` | Only the containerised-mesh test. | |
| `make ui-test` | Playwright against the console, on a stack of local processes with SQLite. `make ui-dev` starts the same stack and leaves it running for manual use. | |
| `make lint` | `go fmt`, Helm lint, then `golangci-lint` in Docker and a dead-code check. Any exported identifier that no binary and no test reaches fails the check, so new exported API must land together with its tests. | about a minute |
| `make verify` | Checks that generated code is current and that no secrets are committed. | |

Put coverage as low in this pyramid as possible. An edge case that a unit or
integration test can cover should not become an end-to-end test. The e2e
suite exists for a small number of critical user journeys and is slow by
nature.

The container tests build images only when they are absent. After you change
a binary, run `make docker-build` before you run them again, or the tests
run the old code.

## A local mesh in kind

`development/kind/` brings up a control plane, a router, a console and Dex
in a local kind cluster with one command. It exposes them through Gateway
API addresses served by `cloud-provider-kind`, which must be installed.

```bash
make kind-up            # create the cluster, build and load images, deploy; opens a tmux log view
make kind-up ARGS=-s    # the same without the log view
make kind-logs          # reattach the log view
make kind-down          # delete everything
```

The mesh comes up with no nodes. Put a service on it with the `sam-node`
chart and one of the examples:

```bash
./development/deploy-kind-service.sh development/examples/calc-mcp
```

The script builds the example's image, loads it into the cluster, and
installs a `sam-node` release with the example's `values.yaml` on top of
`development/kind/sam-node.values.yaml`. Any directory with a `Dockerfile`
and a `values.yaml` works, and extra arguments are passed to Helm.

To use the mesh from a node built from your working tree:

```bash
make kind-local-node                   # mints a bootstrap token, runs ./bin/sam-node, API on 127.0.0.1:9099 with token "devtoken"
make kind-local-node ARGS="--config my-node.yaml"

./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken -tool find_remote_tools -args '{}'
```

`make kind-e2e-mesh` runs the whole loop without interaction. It deploys
`calc-mcp`, enrolls a local node, discovers `mcp://calculator/add`, calls
it, and checks the answer.

## The documentation

The site is Hugo with the Docsy theme, under `site/`. The deploy workflow
pins Hugo 0.136.5, and newer Hugo releases do not build the current Docsy
version, so use that release locally too. Run `npm ci` once in `site/` for
the CSS pipeline, then `hugo server`. The site deploys from `main` to
`sam-mesh.dev`. When a page moves, keep its old URL with `aliases` in the
front matter. `tests/e2e/docs_snippets.bats` runs the Python snippet under
`site/content/docs/snippets/` against a live node, so a change to that
snippet is a change to a test.

## Releases and testnets

A `v*` tag produces a GitHub release with binaries and images through
`goreleaser`, and deploys to the `hub.sam-mesh.dev` testnet. Every push to
`main` deploys to `bananas.sam-mesh.dev`. [Testnets](testnets/) describes
both.
