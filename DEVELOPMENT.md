# Development

How SAM is released. Building, testing and the local kind mesh are described
in the [Contributing](https://sam-mesh.dev/docs/contributing/) pages
(`site/content/docs/contributing/`), and the rules that shape a change are in
[AGENTS.md](AGENTS.md).

## What the repository releases

The repository holds several projects, and each one has its own release
cycle and its own version sequence. The prefix of a git tag selects the
project:

| Project | Tag | Published as | Workflow |
|---|---|---|---|
| The mesh: `sam-node`, `sam-control-plane`, `sam-router`, `sam-one`, `sam-console`, `mcp-client` | `v1.2.3` | A GitHub release with the binaries and `checksums.txt`; the images `ghcr.io/google/sam-*:v1.2.3` and `:stable`; a deployment of `hub.sam-mesh.dev` | `release.yml`, `deploy.yaml` |
| JS SDK | `sdk/js/v1.2.3` | `@sam-mesh/sdk` on npm; a GitHub release | `release.yml` |
| Python SDK | `sdk/python/v1.2.3` | `sam-mesh` on PyPI; a GitHub release | `release.yml` |
| SAM Connect, the Android app | `mobile/v1.2.3` | A GitHub release with the APK and the Play bundle; a Google Play track on a manual run | `mobile.yml` |

A GitHub Actions tag filter does not match `/` with `*`, so a `v*` filter
sees mesh tags only and the other workflows in `.github/workflows/` that
run on `v*` tags are unaffected by SDK and app tags. Only the mesh release
is marked latest on GitHub, and `install.sh` downloads that one.

The Helm charts under `charts/` are installed from a checkout and have no
release cycle of their own.

A version with a hyphen (`v0.2.0-rc.1`, `sdk/js/v0.3.0-beta.2`) is a
prerelease. GitHub marks the release as such, npm publishes it under the
dist-tag `next` so `latest` stays on a stable version, and `pip` skips it
unless the version is requested.

## Cutting a release

1. Run `./hack/release-status.sh`. It prints, for each project, the last
   tag, the commits since that tag under the project's paths, and whether
   the contract the SDKs and the app embed changed since then (see the next
   section).
2. Choose the version from that project's own sequence. The tag prefix is
   fixed; the version follows semantic versioning.
3. Tag a commit on `main` that has passed CI, and push the tag:

   ```bash
   git tag -a sdk/js/v0.3.0 -m sdk/js/v0.3.0
   git push origin sdk/js/v0.3.0
   ```

4. Follow the run under Actions. The mesh run's job summary repeats the
   release status measured at the tag.

To release several projects from the same commit, push their tags together.
The runs are independent and execute in parallel; the versions do not have
to match.

```bash
git tag -a v0.2.0 -m v0.2.0
git tag -a sdk/js/v0.3.0 -m sdk/js/v0.3.0
git tag -a sdk/python/v0.3.1 -m sdk/python/v0.3.1
git push origin v0.2.0 sdk/js/v0.3.0 sdk/python/v0.3.1
```

## When a mesh change needs an SDK or app release

The SDKs and the app are compatible with a mesh release through
`api/sam.proto`, the one schema every component speaks. A mesh release does
not publish them, and most mesh releases do not need one. The cases that do:

| Change in the mesh | Effect on a published SDK or app |
|---|---|
| An additive change to `api/sam.proto` | None. A member ignores fields it does not know, and a control plane ignores fields an older member does not send. |
| A field or endpoint the control plane now requires | Release both SDKs. Make the SDK fail with a clear message against an older control plane, as `controlplane.ts` does for a policy response without `datalog_rules`. |
| `api/datalog.go` | Release both SDKs. `hack/gen-sdk-datalog` embeds it in each SDK as `BASELINE_DATALOG`, together with `sdk/testdata/tar_conformance.json`, and a published SDK keeps enforcing the baseline it was built with. |
| The task-scoped authorization rules (`tar_block`) | Release both SDKs. The Go, TypeScript and Python verifiers must agree. |
| Anything under `internal/node` that a phone should get | Release the app. It embeds `sam-node` through `mobile/sam-node-ffi`. |

Every commit on `main` passes `hack/verify-sdk-generated.sh` and the SDK
integration tests against the control plane built from the same commit, so
the SDKs at HEAD always match the mesh at HEAD. What the release status
tells you is whether the *published* SDKs and app have fallen behind that
contract.

## How each project gets its version

- Go binaries carry the tag in `internal/version.Version` through `ldflags`
  (`.goreleaser.yaml` on a release, `make` locally). `make` derives it with
  `git describe --tags --match 'v*'`, so SDK and app tags in the same history
  do not affect it. Nodes and routers present it as `sam-node/<version>` in
  their `User-Agent`.
- The SDK sources carry a placeholder version. `release.yml` stamps the
  tag's version on the SDK being published with `hack/sdk-version.sh --js`
  or `--python` (package metadata and the client identity the SDK presents
  to MCP peers) and never commits it.
- The app's `version: X.Y.Z+N` in `pubspec.yaml` is overridden at build time:
  the name comes from the tag, the `versionCode` from the workflow run
  number, which Google Play requires to increase on every upload.
- The release notes of an SDK or app release come from
  `hack/release-notes.sh`: the commits since the previous tag with the same
  prefix that touch the project's paths. goreleaser writes the mesh
  changelog, compared against the previous `v*` tag.

## When a run fails

- An SDK publish job: re-run the failed job from the run page, or start
  `release.yml` from the Actions tab with the SDK tag as input. A version
  that is already on npm or PyPI is skipped, so a retry is safe. The GitHub
  release is created after the package is published and is skipped if it
  exists.
- The mesh: re-run the failed job. goreleaser uploads to the release it
  already created for the tag.
- The app: re-run the failed job. The release is created once and the
  artifacts are uploaded with `--clobber`.
- A tag that must not ship is not moved. Cut the next version instead.

## One-time setup

- npm and PyPI trusted publishing is bound to `release.yml` by file name;
  `sdk/README.md` ("Publishing") has the steps a package owner performs
  once on npmjs.com and pypi.org. No publishing token is stored in the
  repository.
- Google Play publishing uses Workload Identity Federation and a service
  account invited in Play Console; `mobile/sam-node-app/README.md` ("From
  CI") lists the repository variables and secrets.
