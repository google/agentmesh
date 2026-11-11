# A Wasmtime capability sandbox on the mesh

Everything the guide at `site/content/docs/guides/wasmtime.md` walks through,
as one standalone Rust supervisor, a WebAssembly text guest (`guest.wat`), and
a Makefile — with no Docker or Kubernetes required:

- a host supervisor that embeds [`wasmtime`](https://github.com/bytecodealliance/wasmtime)
  with a 64 MiB linear-memory cap, fuel + epoch preemption, and zero WASI
  network sockets, filesystem mounts, or environment variables;
- a built-in OIDC discovery + ES256 JWKS server on `127.0.0.1` that mints
  short-lived per-sandbox JWTs (`spiffe://agentmesh.local/wasm/<name>/epoch/<epoch>`)
  outside Wasm linear memory;
- `agentmesh-one` trusting that workload issuer, an edge `agentmesh-node`
  beside the host supervisor (`POST /oauth/token` RFC 7523 `client_credentials`
  and RFC 8693 `token-exchange`), and an office `agentmesh-node` publishing
  `mcp://calc`, `mcp://payroll`, and `mcp://echo-headers`.

```bash
make up                  # start OIDC issuer, agentmesh-one, office-node, and edge-node
make sandbox NAME=demo   # show the SPIFFE ID minted for sandbox demo
make call NAME=demo      # calc allowed, payroll refused by the serving node
make rogue               # a sandbox the policy does not bind: refused
make policy              # push policy.json after you edit it
make check               # run the end-to-end isolation and containment checks
make down                # stop all processes and remove run/
```

Or run the self-contained 8-case verification suite in one command without a
persistent background daemon:

```bash
./run.sh check
```

`run/` holds generated tokens, rendered node configurations, and downloaded
release binaries (if `agentmesh-one` and `agentmesh-node` are not already in
`../../bin` or `PATH`) and is not committed.
