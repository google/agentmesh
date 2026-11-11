;; Copyright 2026 Google LLC
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; Capability-isolated WebAssembly guest module for Agent Mesh.
;;
;; Security properties:
;; - Imports zero WASI sockets, filesystem descriptors, or environment variables.
;; - Imports only `agentmesh_wasi` host functions (`input_len`, `read_input`,
;;   `emit_output`, and `mesh_call`).
;; - Never holds or observes workload JWTs or Agent Mesh Biscuits in linear memory;
;;   the host supervisor performs OIDC minting and RFC 8693 /oauth/token exchange
;;   outside Wasm linear memory.
(module
  (import "agentmesh_wasi" "input_len" (func $input_len (result i32)))
  (import "agentmesh_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
  (import "agentmesh_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
  (import "agentmesh_wasi" "mesh_call" (func $mesh_call (param i32 i32 i32 i32 i32 i32) (result i32)))

  ;; 2 initial pages (128 KiB), 16 max pages (1 MiB) inside the host's 64 MiB store cap.
  (memory (export "memory") 2 16)

  ;; Reads `URI\nJSON_PAYLOAD` from the host input buffer, invokes `agentmesh_wasi::mesh_call`,
  ;; and emits the response bytes (or returns a negative error code such as -5 on 403 AuthZ deny).
  (func (export "run_mesh_call") (result i32)
    (local $len i32)
    (local $read i32)
    (local $i i32)
    (local $uri_len i32)
    (local $req_ptr i32)
    (local $req_len i32)
    (local $resp_len i32)
    (local $byte i32)

    (local.set $len (call $input_len))
    (if (i32.le_s (local.get $len) (i32.const 0))
      (then (return (i32.const -5)))
    )
    (if (i32.gt_s (local.get $len) (i32.const 16384))
      (then (local.set $len (i32.const 16384)))
    )
    (local.set $read (call $read_input (i32.const 0) (local.get $len)))
    (if (i32.le_s (local.get $read) (i32.const 0))
      (then (return (i32.const -5)))
    )

    ;; Split `URI\nPAYLOAD` on newline byte (10)
    (local.set $i (i32.const 0))
    (local.set $uri_len (local.get $read))
    (local.set $req_ptr (i32.const 0))
    (local.set $req_len (i32.const 0))

    (block $scan_done
      (loop $scan
        (br_if $scan_done (i32.ge_u (local.get $i) (local.get $read)))
        (local.set $byte (i32.load8_u (local.get $i)))
        (if (i32.eq (local.get $byte) (i32.const 10))
          (then
            (local.set $uri_len (local.get $i))
            (local.set $req_ptr (i32.add (local.get $i) (i32.const 1)))
            (local.set $req_len (i32.sub (local.get $read) (local.get $req_ptr)))
            (br $scan_done)
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)
      )
    )

    ;; Invoke host PEP bridge: URI at [0..uri_len], request at [req_ptr..req_ptr+req_len],
    ;; response buffer at [32768..98304].
    (local.set $resp_len
      (call $mesh_call
        (i32.const 0)
        (local.get $uri_len)
        (local.get $req_ptr)
        (local.get $req_len)
        (i32.const 32768)
        (i32.const 65536)
      )
    )

    (if (i32.lt_s (local.get $resp_len) (i32.const 0))
      (then (return (local.get $resp_len)))
    )

    (call $emit_output (i32.const 32768) (local.get $resp_len))
  )

  ;; Non-cooperative infinite loop used by `make check` (Case 8) to verify that
  ;; `wasmtime::Engine::increment_epoch()` preempts a spinning guest in < 1ms.
  (func (export "infinite_spin") (result i32)
    (loop $spin
      br $spin
    )
    i32.const 0
  )
)
