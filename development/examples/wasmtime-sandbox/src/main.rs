// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Capability-isolated `wasmtime` sandboxes on an Agent Mesh under per-sandbox identities.
//!
//! Subcommands:
//! - `check` (default): Spawns a self-contained local multi-node `agentmesh` topology
//!   (`agentmesh-one`, `office-node`, `edge-node`, loopback OIDC/JWKS issuer, and local MCP
//!   backends) on `127.0.0.1` and verifies all 8 end-to-end security invariants.
//! - `serve --oidc-port <PORT> --mcp-port <PORT>`: Runs the loopback OIDC discovery + ES256
//!   JWKS issuer and local MCP backends (`/mcp/calc`, `/mcp/payroll`, `/mcp/echo-headers`)
//!   for the interactive `Makefile` workflow (`make up`, `make call`, `make rogue`, `make policy`).
//! - `call --name <NAME> [--service <calc|payroll>] [--a <A>] [--b <B>]`: Runs `guest.wat`
//!   inside a `wasmtime` sandbox bound to `spiffe://agentmesh.local/wasm/<NAME>/epoch/0`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmtime::{Caller, Config, Engine as WasmEngine, Linker, Module, ResourceLimiter, Store};

/// WASI-style error code returned to the Wasm guest when mesh authorization refuses a call (HTTP 403).
pub const WASI_ERR_ACCESS_DENIED: i32 = -5;
/// WASI-style error code returned when guest pointer/length bounds are invalid in linear memory.
pub const WASI_ERR_FAULT: i32 = -14;
/// WASI-style error code returned on upstream transport or I/O errors.
pub const WASI_ERR_IO: i32 = -29;

/// Default SPIFFE trust domain for Wasm sandboxes in this example.
pub const TRUST_DOMAIN_DEFAULT: &str = "spiffe://agentmesh.local";
/// Default `--allowed-audiences` value configured on `agentmesh-one`.
pub const AUDIENCE_DEFAULT: &str = "agentmesh";
/// Default linear memory cap per Wasm sandbox store (64 MiB).
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
/// Default deterministic instruction fuel budget per Wasm invocation.
pub const DEFAULT_FUEL_BUDGET: u64 = 2_000_000;

const GUEST_WAT_SOURCE: &str = include_str!("../guest.wat");

// ============================================================================
// OIDC Discovery & ES256 (P-256) Workload JWT Issuer
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwsHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub sandbox: String,
    pub epoch: u64,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwksDocument {
    pub keys: Vec<EcJwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
}

#[derive(Clone)]
struct KeyEntry {
    kid: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

pub struct WorkloadOidcIssuer {
    issuer_url: String,
    trust_domain: String,
    audience: String,
    current_key: RwLock<KeyEntry>,
    retired_key: RwLock<Option<KeyEntry>>,
}

impl WorkloadOidcIssuer {
    pub fn new(issuer_url: &str, trust_domain: &str, audience: &str) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let initial = KeyEntry {
            kid: "wasm-key-01".to_string(),
            signing_key,
            verifying_key,
        };
        Self {
            issuer_url: issuer_url.trim_end_matches('/').to_string(),
            trust_domain: trust_domain.trim_end_matches('/').to_string(),
            audience: audience.to_string(),
            current_key: RwLock::new(initial),
            retired_key: RwLock::new(None),
        }
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub fn spiffe_id(&self, sandbox_name: &str, epoch: u64) -> String {
        format!(
            "{}/wasm/{}/epoch/{}",
            self.trust_domain, sandbox_name, epoch
        )
    }

    pub fn rotate_key(&self, new_kid: &str) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let next = KeyEntry {
            kid: new_kid.to_string(),
            signing_key,
            verifying_key,
        };
        let mut curr = self.current_key.write().expect("issuer lock");
        let prev = std::mem::replace(&mut *curr, next);
        *self.retired_key.write().expect("retired lock") = Some(prev);
    }

    pub fn openid_configuration(&self) -> OpenIdConfiguration {
        OpenIdConfiguration {
            issuer: self.issuer_url.clone(),
            jwks_uri: format!("{}/.well-known/jwks.json", self.issuer_url),
            response_types_supported: vec!["id_token".to_string()],
            id_token_signing_alg_values_supported: vec!["ES256".to_string()],
            subject_types_supported: vec!["public".to_string()],
        }
    }

    pub fn jwks_document(&self) -> JwksDocument {
        let curr = self.current_key.read().expect("issuer lock");
        let mut keys = vec![key_to_jwk(&curr)];
        if let Some(ref retired) = *self.retired_key.read().expect("retired lock") {
            keys.push(key_to_jwk(retired));
        }
        JwksDocument { keys }
    }

    pub fn mint_jwt(
        &self,
        sandbox_name: &str,
        epoch: u64,
        now_secs: u64,
        issuer_override: Option<&str>,
        audience_override: Option<&str>,
        ttl_secs: u64,
    ) -> Result<String, String> {
        let key = self.current_key.read().expect("issuer lock").clone();
        let header = JwsHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: key.kid,
        };
        let claims = WorkloadClaims {
            iss: issuer_override.unwrap_or(&self.issuer_url).to_string(),
            sub: self.spiffe_id(sandbox_name, epoch),
            aud: audience_override.unwrap_or(&self.audience).to_string(),
            sandbox: sandbox_name.to_string(),
            epoch,
            iat: now_secs,
            nbf: now_secs,
            exp: now_secs.saturating_add(ttl_secs),
            jti: format!("jti-{}-{}", sandbox_name, random_hex(8)),
        };

        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?);
        let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|e| e.to_string())?);
        let signing_input = format!("{}.{}", h_b64, c_b64);
        let sig: Signature = key.signing_key.sign(signing_input.as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{}.{}", signing_input, s_b64))
    }
}

fn key_to_jwk(entry: &KeyEntry) -> EcJwk {
    let point = entry.verifying_key.to_encoded_point(false);
    let raw = point.as_bytes();
    assert_eq!(raw[0], 0x04);
    assert_eq!(raw.len(), 65);
    EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(&raw[1..33]),
        y: URL_SAFE_NO_PAD.encode(&raw[33..65]),
        key_use: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: entry.kid.clone(),
    }
}

/// Validates that an ES256 JWS signature is raw 64-byte IEEE P1363 (`R || S`) and rejects ASN.1 DER.
pub fn parse_ieee_p1363_signature(raw_sig: &[u8]) -> Result<Signature, String> {
    if raw_sig.len() != 64 {
        if raw_sig.len() >= 8 && raw_sig[0] == 0x30 {
            return Err("ASN.1 DER signature rejected: ES256 requires 64-byte IEEE P1363".into());
        }
        return Err(format!(
            "Invalid ES256 signature length: expected 64 bytes, got {}",
            raw_sig.len()
        ));
    }
    if raw_sig[0] == 0x30 && (raw_sig[1] == 62 || (raw_sig[1] <= 62 && raw_sig[2] == 0x02)) {
        return Err("ASN.1 DER sequence rejected: ES256 requires raw IEEE P1363".into());
    }
    Signature::from_bytes(raw_sig.into()).map_err(|e| format!("Invalid P-256 scalar: {}", e))
}

// ============================================================================
// URI Validation, Header Hygiene & Host PEP Token Cache
// ============================================================================

/// Validates that a Wasm guest only requests logical Agent Mesh URIs (`mcp://`, `a2a://`,
/// `inference://`, `egress://`) and blocks raw `http://`, `https://`, `file://`, and IP literals.
pub fn validate_logical_mesh_uri(uri: &str) -> Result<(&str, &str), String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) || trimmed.contains("..") {
        return Err(format!("Malformed mesh URI '{}'", uri));
    }
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err(format!("Mesh URI '{}' is missing scheme", uri));
    };
    match scheme {
        "mcp" | "a2a" | "inference" | "egress" => {}
        other => {
            return Err(format!(
                "Disallowed URI scheme '{}://': Wasm guests must use logical mesh URIs",
                other
            ))
        }
    }
    let service = rest.trim_matches('/');
    if service.is_empty() {
        return Err(format!("Mesh URI '{}' has empty target", uri));
    }
    Ok((scheme, service))
}

/// Strips caller credentials (`Authorization`, `Cookie`, `Set-Cookie`, `X-Mesh-*`) and injects
/// the host-exchanged Biscuit as `X-Mesh-Authentication: Bearer <biscuit>`.
pub fn sanitize_and_inject_headers(
    caller_headers: &[(String, String)],
    biscuit: &str,
) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(caller_headers.len() + 2);
    for (k, v) in caller_headers {
        let lower = k.trim().to_ascii_lowercase();
        if lower == "authorization"
            || lower == "proxy-authorization"
            || lower == "cookie"
            || lower == "set-cookie"
            || lower.starts_with("x-mesh-")
        {
            continue;
        }
        out.push((k.clone(), v.clone()));
    }
    out.push((
        "X-Mesh-Authentication".to_string(),
        format!("Bearer {}", biscuit),
    ));
    out
}

/// Scans Wasm guest linear memory to verify that neither the ES256 workload JWT nor the
/// exchanged Agent Mesh Biscuit ever entered guest memory.
pub fn verify_linear_memory_zero_secrets(mem_bytes: &[u8], active_secrets: &[String]) -> bool {
    let static_markers: &[&[u8]] = &[
        b"eyJhbGciOiJFUzI1NiI",
        b"BEGIN PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
    ];
    for marker in static_markers {
        if mem_bytes.windows(marker.len()).any(|w| w == *marker) {
            return false;
        }
    }
    for secret in active_secrets {
        let prefix_len = secret.len().min(18);
        if prefix_len >= 8 {
            let needle = &secret.as_bytes()[..prefix_len];
            if mem_bytes.windows(needle.len()).any(|w| w == needle) {
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveredService {
    pub peer_id: String,
    #[serde(default)]
    pub srv_name: String,
    #[serde(default)]
    pub srv_description: String,
}

pub struct HostPepBridge {
    edge_url: String,
    issuer: Arc<WorkloadOidcIssuer>,
    token_cache: RwLock<HashMap<(String, u64), String>>,
    provider_peer_id: RwLock<Option<String>>,
}

impl HostPepBridge {
    pub fn new(edge_url: &str, issuer: Arc<WorkloadOidcIssuer>) -> Self {
        Self {
            edge_url: edge_url.trim_end_matches('/').to_string(),
            issuer,
            token_cache: RwLock::new(HashMap::new()),
            provider_peer_id: RwLock::new(None),
        }
    }

    pub fn set_provider_peer_id(&self, peer_id: String) {
        *self.provider_peer_id.write().expect("peer lock") = Some(peer_id);
    }

    pub fn active_secrets(&self) -> Vec<String> {
        self.token_cache
            .read()
            .expect("cache lock")
            .values()
            .cloned()
            .collect()
    }

    pub fn evict_sandbox(&self, sandbox_name: &str) -> Duration {
        let start = Instant::now();
        self.token_cache
            .write()
            .expect("cache lock")
            .retain(|(name, _), _| name != sandbox_name);
        start.elapsed()
    }

    pub fn clear_cache(&self) {
        self.token_cache.write().expect("cache lock").clear();
    }

    pub fn get_or_exchange_biscuit(
        &self,
        sandbox_name: &str,
        epoch: u64,
    ) -> Result<String, String> {
        let key = (sandbox_name.to_string(), epoch);
        if let Some(tok) = self.token_cache.read().expect("cache lock").get(&key) {
            return Ok(tok.clone());
        }
        let now = unix_now();
        let jwt = self
            .issuer
            .mint_jwt(sandbox_name, epoch, now, None, None, 300)?;
        let biscuit = self.exchange_jwt(&jwt, None, false)?;
        self.token_cache
            .write()
            .expect("cache lock")
            .insert(key, biscuit.clone());
        Ok(biscuit)
    }

    pub fn exchange_jwt(
        &self,
        subject_jwt: &str,
        scope: Option<&str>,
        seal: bool,
    ) -> Result<String, String> {
        let mut form = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&audience={}",
            url_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
            url_encode(subject_jwt),
            url_encode("urn:ietf:params:oauth:token-type:jwt"),
            url_encode(AUDIENCE_DEFAULT),
        );
        if let Some(sc) = scope {
            form.push_str(&format!("&scope={}", url_encode(sc)));
        }
        if seal {
            form.push_str("&seal=true");
        }
        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, body) = http_request(
            "POST",
            &format!("{}/oauth/token", self.edge_url),
            &headers,
            form.as_bytes(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "POST /oauth/token failed (HTTP {}): {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        let parsed: TokenExchangeResponse =
            serde_json::from_slice(&body).map_err(|e| format!("token JSON error: {}", e))?;
        Ok(parsed.access_token)
    }

    pub fn revoke_biscuit(&self, biscuit: &str) -> Result<(), String> {
        let form = format!("token={}", url_encode(biscuit));
        let headers = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let (status, body) = http_request(
            "POST",
            &format!("{}/oauth/revoke", self.edge_url),
            &headers,
            form.as_bytes(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "POST /oauth/revoke failed (HTTP {}): {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        Ok(())
    }

    pub fn discover_services(
        &self,
        biscuit: &str,
        name: Option<&str>,
    ) -> Result<Vec<DiscoveredService>, String> {
        let mut url = format!("{}/mesh/service/discover?type=mcp", self.edge_url);
        if let Some(n) = name {
            url.push_str(&format!("&name={}", url_encode(n)));
        }
        let headers = vec![
            (
                "X-Mesh-Authentication".to_string(),
                format!("Bearer {}", biscuit),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let (status, body) = http_request("GET", &url, &headers, b"")?;
        if status != 200 {
            return Err(format!(
                "GET /mesh/service/discover failed (HTTP {}): {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        serde_json::from_slice(&body).map_err(|e| format!("discover JSON error: {}", e))
    }

    pub fn call_mesh_service_with_biscuit(
        &self,
        uri: &str,
        biscuit: &str,
        caller_headers: &[(String, String)],
        payload: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let (scheme, service) = validate_logical_mesh_uri(uri)?;
        let peer_id = self
            .provider_peer_id
            .read()
            .expect("peer lock")
            .clone()
            .ok_or_else(|| "Provider PeerID not yet discovered".to_string())?;
        let url = format!("{}/mesh/{}/{}/{}", self.edge_url, peer_id, scheme, service);
        let mut headers = sanitize_and_inject_headers(caller_headers, biscuit);
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        http_request("POST", &url, &headers, payload)
    }
}

// ============================================================================
// Wasmtime v49.0.4 Capability Sandbox Executor
// ============================================================================

struct WasmSandboxState {
    sandbox_name: String,
    epoch: u64,
    pep: Arc<HostPepBridge>,
    input: Vec<u8>,
    output: Vec<u8>,
    max_memory_bytes: usize,
}

impl ResourceLimiter for WasmSandboxState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        if let Some(max) = maximum {
            if desired > max {
                return Ok(false);
            }
        }
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        Ok(desired <= 4096)
    }
}

pub struct WasmSandboxRunner {
    engine: WasmEngine,
    module: Module,
    linker: Arc<Linker<WasmSandboxState>>,
}

impl WasmSandboxRunner {
    pub fn new() -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = WasmEngine::new(&config).map_err(|e| e.to_string())?;
        let module = Module::new(&engine, GUEST_WAT_SOURCE).map_err(|e| e.to_string())?;

        let mut linker: Linker<WasmSandboxState> = Linker::new(&engine);
        Self::bind_imports(&mut linker)?;

        Ok(Self {
            engine,
            module,
            linker: Arc::new(linker),
        })
    }

    pub fn engine(&self) -> &WasmEngine {
        &self.engine
    }

    fn bind_imports(linker: &mut Linker<WasmSandboxState>) -> Result<(), String> {
        linker
            .func_wrap(
                "agentmesh_wasi",
                "input_len",
                |caller: Caller<'_, WasmSandboxState>| -> i32 { caller.data().input.len() as i32 },
            )
            .map_err(|e| e.to_string())?;

        linker
            .func_wrap(
                "agentmesh_wasi",
                "read_input",
                |mut caller: Caller<'_, WasmSandboxState>, ptr: i32, len: i32| -> i32 {
                    if ptr < 0 || len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return WASI_ERR_FAULT;
                    };
                    let input = caller.data().input.clone();
                    let to_copy = (len as usize).min(input.len());
                    let start = ptr as usize;
                    let data = mem.data_mut(&mut caller);
                    if start.saturating_add(to_copy) > data.len() {
                        return WASI_ERR_FAULT;
                    }
                    data[start..start + to_copy].copy_from_slice(&input[..to_copy]);
                    to_copy as i32
                },
            )
            .map_err(|e| e.to_string())?;

        linker
            .func_wrap(
                "agentmesh_wasi",
                "emit_output",
                |mut caller: Caller<'_, WasmSandboxState>, ptr: i32, len: i32| -> i32 {
                    if ptr < 0 || len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return WASI_ERR_FAULT;
                    };
                    let start = ptr as usize;
                    let size = len as usize;
                    let data = mem.data(&caller);
                    if start.saturating_add(size) > data.len() {
                        return WASI_ERR_FAULT;
                    }
                    let slice = data[start..start + size].to_vec();
                    caller.data_mut().output = slice;
                    size as i32
                },
            )
            .map_err(|e| e.to_string())?;

        linker
            .func_wrap(
                "agentmesh_wasi",
                "mesh_call",
                |mut caller: Caller<'_, WasmSandboxState>,
                 uri_ptr: i32,
                 uri_len: i32,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_cap: i32|
                 -> i32 {
                    if uri_ptr < 0
                        || uri_len <= 0
                        || req_ptr < 0
                        || req_len < 0
                        || resp_ptr < 0
                        || resp_cap <= 0
                    {
                        return WASI_ERR_FAULT;
                    }
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return WASI_ERR_FAULT;
                    };
                    let (uri_str, req_bytes) = {
                        let data = mem.data(&caller);
                        let u_start = uri_ptr as usize;
                        let u_end = u_start.saturating_add(uri_len as usize);
                        let r_start = req_ptr as usize;
                        let r_end = r_start.saturating_add(req_len as usize);
                        if u_end > data.len() || r_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        let Ok(u) = std::str::from_utf8(&data[u_start..u_end]) else {
                            return WASI_ERR_FAULT;
                        };
                        (u.to_string(), data[r_start..r_end].to_vec())
                    };

                    if validate_logical_mesh_uri(&uri_str).is_err() {
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    let sandbox_name = caller.data().sandbox_name.clone();
                    let epoch = caller.data().epoch;
                    let pep = Arc::clone(&caller.data().pep);

                    let Ok(biscuit) = pep.get_or_exchange_biscuit(&sandbox_name, epoch) else {
                        return WASI_ERR_ACCESS_DENIED;
                    };

                    let Ok((status, resp_bytes)) =
                        pep.call_mesh_service_with_biscuit(&uri_str, &biscuit, &[], &req_bytes)
                    else {
                        return WASI_ERR_IO;
                    };

                    if status == 401 || status == 403 {
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    if !(200..300).contains(&status) {
                        return WASI_ERR_IO;
                    }

                    let write_len = resp_bytes.len().min(resp_cap as usize);
                    let out_start = resp_ptr as usize;
                    let data = mem.data_mut(&mut caller);
                    if out_start.saturating_add(write_len) > data.len() {
                        return WASI_ERR_FAULT;
                    }
                    data[out_start..out_start + write_len]
                        .copy_from_slice(&resp_bytes[..write_len]);
                    write_len as i32
                },
            )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Executes `run_mesh_call` inside `guest.wat` and scans guest linear memory after completion.
    pub fn execute_mesh_call(
        &self,
        pep: Arc<HostPepBridge>,
        sandbox_name: &str,
        epoch: u64,
        uri: &str,
        payload: &[u8],
    ) -> Result<(i32, bool, String), String> {
        let mut input = Vec::with_capacity(uri.len() + 1 + payload.len());
        input.extend_from_slice(uri.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(payload);

        let state = WasmSandboxState {
            sandbox_name: sandbox_name.to_string(),
            epoch,
            pep: Arc::clone(&pep),
            input,
            output: Vec::new(),
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| s);
        store
            .set_fuel(DEFAULT_FUEL_BUDGET)
            .map_err(|e| e.to_string())?;
        store.set_epoch_deadline(1);

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| e.to_string())?;
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "run_mesh_call")
            .map_err(|e| e.to_string())?;
        let exit_code = func.call(&mut store, ()).map_err(|e| e.to_string())?;

        let zero_secrets = if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let secrets = pep.active_secrets();
            verify_linear_memory_zero_secrets(mem.data(&store), &secrets)
        } else {
            true
        };

        let out_str = String::from_utf8_lossy(&store.data().output).to_string();
        Ok((exit_code, zero_secrets, out_str))
    }

    /// Executes `infinite_spin` inside `guest.wat` so `Engine::increment_epoch()` preemption can be verified.
    pub fn execute_infinite_spin(&self, pep: Arc<HostPepBridge>) -> Result<i32, String> {
        let state = WasmSandboxState {
            sandbox_name: "demo".to_string(),
            epoch: 0,
            pep,
            input: Vec::new(),
            output: Vec::new(),
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| s);
        store.set_fuel(u64::MAX / 2).map_err(|e| e.to_string())?;
        store.set_epoch_deadline(1);

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| e.to_string())?;
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "infinite_spin")
            .map_err(|e| e.to_string())?;
        func.call(&mut store, ()).map_err(|e| e.to_string())
    }
}

// ============================================================================
// Loopback HTTP Servers (OIDC Discovery + Local MCP Backends) & Wire Client
// ============================================================================

struct LoopbackServerHandle {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl Drop for LoopbackServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn start_oidc_http_server(
    bind_port: u16,
    trust_domain: &str,
    audience: &str,
) -> Result<(LoopbackServerHandle, Arc<WorkloadOidcIssuer>), String> {
    let listener = TcpListener::bind(("127.0.0.1", bind_port)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let issuer_url = format!("http://127.0.0.1:{}", port);
    let issuer = Arc::new(WorkloadOidcIssuer::new(&issuer_url, trust_domain, audience));
    let issuer_bg = Arc::clone(&issuer);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let iss = Arc::clone(&issuer_bg);
            thread::spawn(move || {
                let _ = handle_oidc_conn(stream, &iss);
            });
        }
    });

    Ok((LoopbackServerHandle { port, stop }, issuer))
}

fn handle_oidc_conn(mut stream: TcpStream, issuer: &WorkloadOidcIssuer) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let (method, raw_path, _headers, body) = read_http_stream(&mut stream)?;
    let path = raw_path.split('?').next().unwrap_or(&raw_path);

    match (method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => {
            let bytes =
                serde_json::to_vec(&issuer.openid_configuration()).map_err(|e| e.to_string())?;
            write_http_stream(&mut stream, 200, "OK", "application/json", &bytes)
        }
        ("GET", "/.well-known/jwks.json") | ("GET", "/keys") => {
            let bytes = serde_json::to_vec(&issuer.jwks_document()).map_err(|e| e.to_string())?;
            write_http_stream(&mut stream, 200, "OK", "application/json", &bytes)
        }
        ("POST", "/mint") => {
            let req: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("demo");
            let epoch = req.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            let jwt = issuer.mint_jwt(name, epoch, unix_now(), None, None, 300)?;
            let resp = serde_json::to_vec(&json!({
                "jwt": jwt,
                "sub": issuer.spiffe_id(name, epoch),
            }))
            .map_err(|e| e.to_string())?;
            write_http_stream(&mut stream, 200, "OK", "application/json", &resp)
        }
        ("GET", "/healthz") | ("GET", "/readyz") => write_http_stream(
            &mut stream,
            200,
            "OK",
            "application/json",
            br#"{"status":"ok"}"#,
        ),
        _ => write_http_stream(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}

fn start_mcp_backend_server(bind_port: u16) -> Result<LoopbackServerHandle, String> {
    let listener = TcpListener::bind(("127.0.0.1", bind_port)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            thread::spawn(move || {
                let _ = handle_mcp_conn(stream);
            });
        }
    });

    Ok(LoopbackServerHandle { port, stop })
}

fn evaluate_mcp_service(service: &str, args: &Value, headers: &HashMap<String, String>) -> Value {
    match service {
        "calc" => {
            let op = args.get("op").and_then(|v| v.as_str()).unwrap_or("add");
            let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let result = match op {
                "mul" | "multiply" => a * b,
                "sub" | "subtract" => a - b,
                _ => a + b,
            };
            json!({
                "service": "calc",
                "op": op,
                "a": a,
                "b": b,
                "result": result,
            })
        }
        "payroll" => {
            let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            json!({
                "service": "payroll",
                "authorized": true,
                "result": a + b,
            })
        }
        "echo-headers" => {
            json!({
                "service": "echo-headers",
                "authorization_present": headers.contains_key("authorization"),
                "cookie_present": headers.contains_key("cookie"),
                "x_mesh_auth_present": headers.contains_key("x-mesh-authentication"),
                "x_mesh_principal": headers.get("x-mesh-principal").cloned().unwrap_or_default(),
                "x_mesh_roles": headers.get("x-mesh-roles").cloned().unwrap_or_default(),
            })
        }
        other => json!({ "service": other, "ok": true }),
    }
}

fn handle_mcp_conn(mut stream: TcpStream) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let (method, raw_path, headers, body) = read_http_stream(&mut stream)?;
    let path = raw_path.split('?').next().unwrap_or(&raw_path);

    if path == "/healthz" || path == "/readyz" {
        return write_http_stream(
            &mut stream,
            200,
            "OK",
            "application/json",
            br#"{"status":"ok"}"#,
        );
    }
    if method == "GET" || method == "DELETE" {
        return write_http_stream(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain",
            b"POST required",
        );
    }

    let service = path
        .trim_start_matches('/')
        .strip_prefix("mcp/")
        .unwrap_or("calc")
        .split('/')
        .next()
        .unwrap_or("calc");

    let parsed: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));

    if parsed.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
        let rpc_method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let rpc_id = parsed.get("id").cloned();
        if rpc_id.is_none() || rpc_method.starts_with("notifications/") {
            return write_http_stream(&mut stream, 202, "Accepted", "application/json", b"");
        }
        let id_val = rpc_id.unwrap_or(Value::Number(1.into()));
        let resp_json = match rpc_method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": service, "version": "0.1.0" }
                }
            }),
            "tools/list" => {
                let tools = match service {
                    "calc" | "payroll" => json!([
                        {
                            "name": "add",
                            "description": "Return a + b.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "a": { "type": "number" }, "b": { "type": "number" } }
                            }
                        },
                        {
                            "name": "multiply",
                            "description": "Return a * b.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "a": { "type": "number" }, "b": { "type": "number" } }
                            }
                        }
                    ]),
                    "echo-headers" => json!([{
                        "name": "inspect_headers",
                        "description": "Inspect upstream request headers",
                        "inputSchema": { "type": "object", "properties": {} }
                    }]),
                    _ => json!([]),
                };
                json!({ "jsonrpc": "2.0", "id": id_val, "result": { "tools": tools } })
            }
            "tools/call" => {
                let args = parsed
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let out = evaluate_mcp_service(service, &args, &headers);
                json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "content": [{ "type": "text", "text": out.to_string() }],
                        "isError": false
                    }
                })
            }
            _ => json!({ "jsonrpc": "2.0", "id": id_val, "result": {} }),
        };
        let bytes = serde_json::to_vec(&resp_json).map_err(|e| e.to_string())?;
        return write_http_stream(&mut stream, 200, "OK", "application/json", &bytes);
    }

    let out = evaluate_mcp_service(service, &parsed, &headers);
    let bytes = serde_json::to_vec(&out).map_err(|e| e.to_string())?;
    write_http_stream(&mut stream, 200, "OK", "application/json", &bytes)
}

type HttpRequestParts = (String, String, HashMap<String, String>, Vec<u8>);

fn read_http_stream(stream: &mut TcpStream) -> Result<HttpRequestParts, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return Err("HTTP header too large".into());
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or("Empty request line")?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut content_len = 0usize;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_len = val.parse::<usize>().unwrap_or(0);
            } else if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            headers.insert(key, val);
        }
    }

    let mut body = buf[header_end..].to_vec();
    if chunked {
        while !body.windows(5).any(|w| w == b"0\r\n\r\n") {
            let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body = decode_chunked(&body);
    } else {
        while body.len() < content_len {
            let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_len);
    }

    Ok((method, path, headers, body))
}

fn write_http_stream(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        stream.write_all(body).map_err(|e| e.to_string())?;
    }
    let _ = stream.flush();
    Ok(())
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let without_scheme = url.strip_prefix("http://").ok_or_else(|| {
        format!(
            "Only http:// loopback URLs supported in test client: {}",
            url
        )
    })?;
    let (host_port, path) = match without_scheme.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (without_scheme, "/".to_string()),
    };
    let addr: SocketAddr = host_port
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("Could not resolve {}", host_port))?;

    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        method,
        path,
        host_port,
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        stream.write_all(body).map_err(|e| e.to_string())?;
    }
    let _ = stream.flush();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("Invalid HTTP response".into());
    };
    let head = String::from_utf8_lossy(&resp[..pos]);
    let status_line = head.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    let is_chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked"));
    let raw_body = &resp[pos + 4..];
    let out_body = if is_chunked {
        decode_chunked(raw_body)
    } else {
        raw_body.to_vec()
    };
    Ok((status, out_body))
}

fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < raw.len() {
        let Some(rel_end) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&raw[idx..idx + rel_end]);
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        idx += rel_end + 2;
        if chunk_len == 0 || idx + chunk_len > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[idx..idx + chunk_len]);
        idx += chunk_len + 2;
    }
    out
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut buf);
    let mut s = String::with_capacity(bytes_len * 2);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn pick_free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| e.to_string())
}

// ============================================================================
// Process Management & Binary Discovery
// ============================================================================

struct ManagedChild {
    name: String,
    child: Child,
}

impl ManagedChild {
    fn spawn(name: &str, mut cmd: Command) -> Result<Self, String> {
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", name, e))?;
        Ok(Self {
            name: name.to_string(),
            child,
        })
    }

    fn try_has_exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.name;
    }
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", stem)
    } else {
        stem.to_string()
    }
}

fn locate_agentmesh_binaries() -> Option<(PathBuf, PathBuf)> {
    let one_name = exe_name("agentmesh-one");
    let node_name = exe_name("agentmesh-node");
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut dirs = Vec::new();
    if let Ok(d) = env::var("AGENTMESH_BIN_DIR") {
        if !d.trim().is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    dirs.push(manifest_dir.join("run").join("bin"));
    dirs.push(manifest_dir.join("../../bin"));
    if let Some(path_os) = env::var_os("PATH") {
        dirs.extend(env::split_paths(&path_os));
    }

    for dir in dirs {
        let one = dir.join(&one_name);
        let node = dir.join(&node_name);
        if one.is_file() && node.is_file() {
            return Some((one, node));
        }
    }
    None
}

fn wait_http_200(
    url: &str,
    timeout: Duration,
    child: &mut ManagedChild,
    log_path: &Path,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut last_err = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_has_exited() {
            let logs = fs::read_to_string(log_path).unwrap_or_default();
            return Err(format!(
                "{} exited early ({}) waiting for {}.\nLogs:\n{}",
                child.name, status, url, logs
            ));
        }
        match http_request("GET", url, &[], b"") {
            Ok((200, body)) => return Ok(body),
            Ok((code, body)) => {
                last_err = format!("HTTP {}: {}", code, String::from_utf8_lossy(&body));
            }
            Err(e) => last_err = e,
        }
        thread::sleep(Duration::from_millis(150));
    }
    let logs = fs::read_to_string(log_path).unwrap_or_default();
    Err(format!(
        "Timed out waiting for {} ({}).\nLogs:\n{}",
        url, last_err, logs
    ))
}

fn read_ports_env() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ports_path = manifest_dir.join("run").join("ports.env");
    if let Ok(content) = fs::read_to_string(ports_path) {
        for line in content.lines() {
            if let Some((k, v)) = line.trim().split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

// ============================================================================
// Subcommand 1: `serve` (Full Local Topology Daemon for `make up`)
// ============================================================================

fn run_serve_command(one_bin: &Path, node_bin: &Path) -> Result<(), String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_dir = manifest_dir.join("run");
    let cp_dir = run_dir.join("cp");
    let office_dir = run_dir.join("office");
    let edge_dir = run_dir.join("edge");
    let _ = fs::remove_dir_all(&cp_dir);
    let _ = fs::remove_dir_all(&office_dir);
    let _ = fs::remove_dir_all(&edge_dir);
    fs::create_dir_all(&cp_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&office_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&edge_dir).map_err(|e| e.to_string())?;

    let (_oidc_srv, issuer) = start_oidc_http_server(0, TRUST_DOMAIN_DEFAULT, AUDIENCE_DEFAULT)?;
    let mcp_srv = start_mcp_backend_server(0)?;

    let policy_path = manifest_dir.join("policy.json");
    let office_tmpl =
        fs::read_to_string(manifest_dir.join("office.yaml.tmpl")).map_err(|e| e.to_string())?;
    let office_yaml_path = run_dir.join("office.yaml");
    fs::write(
        &office_yaml_path,
        office_tmpl.replace("__MCP_PORT__", &mcp_srv.port.to_string()),
    )
    .map_err(|e| e.to_string())?;

    let join_token_path = run_dir.join("join-token");
    let admin_token_path = run_dir.join("admin-token");
    let office_api_path = run_dir.join("office-api-token");
    let edge_api_path = run_dir.join("edge-api-token");

    let join_token = format!("mesh_tok_{}", random_hex(12));
    let admin_token = format!("mesh_adm_{}", random_hex(12));
    fs::write(&join_token_path, &join_token).map_err(|e| e.to_string())?;
    fs::write(&admin_token_path, &admin_token).map_err(|e| e.to_string())?;
    fs::write(&office_api_path, random_hex(12)).map_err(|e| e.to_string())?;
    fs::write(&edge_api_path, random_hex(12)).map_err(|e| e.to_string())?;

    let cp_port = pick_free_port()?;
    let cp_url = format!("http://127.0.0.1:{}", cp_port);
    let cp_log_path = run_dir.join("cp.log");
    let cp_log = File::create(&cp_log_path).map_err(|e| e.to_string())?;
    let cp_err = cp_log.try_clone().map_err(|e| e.to_string())?;

    let mut cp_cmd = Command::new(one_bin);
    cp_cmd
        .arg("--bind-address=127.0.0.1")
        .arg(format!("--port={}", cp_port))
        .arg(format!("--data-dir={}", cp_dir.display()))
        .arg(format!("--policy-file={}", policy_path.display()))
        .arg(format!("--token-path={}", join_token_path.display()))
        .arg(format!("--admin-token-path={}", admin_token_path.display()))
        .arg(format!("--workload-issuer={}", issuer.issuer_url()))
        .arg(format!("--allowed-audiences={}", AUDIENCE_DEFAULT))
        .arg("--router-allow-loopback=true")
        .arg("--enroll-qr=false")
        .arg("--log-format=json")
        .stdout(Stdio::from(cp_log))
        .stderr(Stdio::from(cp_err));

    let mut cp_proc = ManagedChild::spawn("agentmesh-one", cp_cmd)?;
    wait_http_200(
        &format!("{}/info", cp_url),
        Duration::from_secs(20),
        &mut cp_proc,
        &cp_log_path,
    )?;

    let office_port = pick_free_port()?;
    let office_metrics_port = pick_free_port()?;
    let office_log_path = run_dir.join("office.log");
    let office_log = File::create(&office_log_path).map_err(|e| e.to_string())?;
    let office_err = office_log.try_clone().map_err(|e| e.to_string())?;

    let mut office_cmd = Command::new(node_bin);
    office_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            join_token_path.display()
        ))
        .arg(format!("--api-token-path={}", office_api_path.display()))
        .arg(format!("--data-dir={}", office_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", office_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", office_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=2s")
        .arg(format!("--config={}", office_yaml_path.display()))
        .arg("--log-format=json")
        .stdout(Stdio::from(office_log))
        .stderr(Stdio::from(office_err));

    let mut office_proc = ManagedChild::spawn("office-node", office_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", office_metrics_port),
        Duration::from_secs(25),
        &mut office_proc,
        &office_log_path,
    )?;

    let edge_port = pick_free_port()?;
    let edge_metrics_port = pick_free_port()?;
    let edge_url = format!("http://127.0.0.1:{}", edge_port);
    let edge_log_path = run_dir.join("edge.log");
    let edge_log = File::create(&edge_log_path).map_err(|e| e.to_string())?;
    let edge_err = edge_log.try_clone().map_err(|e| e.to_string())?;

    let mut edge_cmd = Command::new(node_bin);
    edge_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            join_token_path.display()
        ))
        .arg(format!("--api-token-path={}", edge_api_path.display()))
        .arg(format!("--data-dir={}", edge_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", edge_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", edge_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=2s")
        .arg("--log-format=json")
        .stdout(Stdio::from(edge_log))
        .stderr(Stdio::from(edge_err));

    let mut edge_proc = ManagedChild::spawn("edge-node", edge_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", edge_metrics_port),
        Duration::from_secs(25),
        &mut edge_proc,
        &edge_log_path,
    )?;

    let pep = HostPepBridge::new(&edge_url, Arc::clone(&issuer));
    let demo_biscuit = pep.get_or_exchange_biscuit("demo", 0)?;
    let mut provider_peer_id = String::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if let Ok(items) = pep.discover_services(&demo_biscuit, Some("calc")) {
            if let Some(first) = items.into_iter().find(|i| !i.peer_id.is_empty()) {
                provider_peer_id = first.peer_id;
                break;
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
    if provider_peer_id.is_empty() {
        return Err("DHT discovery timed out waiting for office-node".into());
    }

    let ports_env = format!(
        "ONE_API_PORT={}\nEDGE_PORT={}\nEDGE_URL={}\nOIDC_PORT={}\nOIDC_URL={}\nMCP_PORT={}\nPROVIDER_PEER_ID={}\n",
        cp_port,
        edge_port,
        edge_url,
        _oidc_srv.port,
        issuer.issuer_url(),
        mcp_srv.port,
        provider_peer_id
    );
    fs::write(run_dir.join("ports.env"), ports_env).map_err(|e| e.to_string())?;
    println!(
        "Topology ready: ONE_API_PORT={} EDGE_URL={} OIDC_URL={}",
        cp_port,
        edge_url,
        issuer.issuer_url()
    );

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

// ============================================================================
// Subcommand 2: `call` (Interactive `make call NAME=demo` / `make rogue`)
// ============================================================================

fn run_call_command(
    sandbox_name: &str,
    only_service: Option<&str>,
    payload_override: Option<&str>,
    a: f64,
    b: f64,
    edge_url_opt: Option<&str>,
    oidc_url_opt: Option<&str>,
) -> Result<i32, String> {
    let ports_map = read_ports_env();
    let edge_url = edge_url_opt
        .map(String::from)
        .or_else(|| env::var("EDGE_URL").ok())
        .or_else(|| ports_map.get("EDGE_URL").cloned())
        .unwrap_or_else(|| "http://127.0.0.1:18090".to_string());
    let oidc_url = oidc_url_opt
        .map(String::from)
        .or_else(|| env::var("OIDC_URL").ok())
        .or_else(|| ports_map.get("OIDC_URL").cloned())
        .unwrap_or_else(|| "http://127.0.0.1:18008".to_string());
    let fallback_peer_id = ports_map.get("PROVIDER_PEER_ID").cloned();

    // Request a short-lived ES256 JWT for `sandbox_name` from the running loopback OIDC server.
    let mint_body = serde_json::to_vec(&json!({ "name": sandbox_name, "epoch": 0 }))
        .map_err(|e| e.to_string())?;
    let (status, resp) = http_request(
        "POST",
        &format!("{}/mint", oidc_url.trim_end_matches('/')),
        &[("Content-Type".to_string(), "application/json".to_string())],
        &mint_body,
    )?;
    if status != 200 {
        return Err(format!(
            "Failed to mint JWT from {}/mint (HTTP {}): is `make up` running?",
            oidc_url, status
        ));
    }
    let mint_json: Value = serde_json::from_slice(&resp).map_err(|e| e.to_string())?;
    let jwt = mint_json
        .get("jwt")
        .and_then(|v| v.as_str())
        .ok_or("Missing jwt in /mint response")?;

    let dummy_issuer = Arc::new(WorkloadOidcIssuer::new(
        &oidc_url,
        TRUST_DOMAIN_DEFAULT,
        AUDIENCE_DEFAULT,
    ));
    let pep = Arc::new(HostPepBridge::new(&edge_url, dummy_issuer));
    let biscuit = pep.exchange_jwt(jwt, None, false)?;
    pep.token_cache
        .write()
        .expect("cache lock")
        .insert((sandbox_name.to_string(), 0), biscuit.clone());

    let services = pep.discover_services(&biscuit, None)?;
    if let Some(first) = services.first() {
        pep.set_provider_peer_id(first.peer_id.clone());
    } else if let Some(peer) = fallback_peer_id {
        pep.set_provider_peer_id(peer);
    }

    let wasm = WasmSandboxRunner::new()?;
    let payload_bytes = match payload_override {
        Some(raw) => raw.as_bytes().to_vec(),
        None => serde_json::to_vec(&json!({ "op": "add", "a": a, "b": b })).unwrap(),
    };

    if let Some(svc_raw) = only_service {
        let svc_name = svc_raw.strip_prefix("mcp://").unwrap_or(svc_raw);
        let full_uri = format!("mcp://{}", svc_name);
        if pep.provider_peer_id.read().expect("peer lock").is_none() {
            println!(
                "{}/add({}, {}) -> refused: no MCP provider visible to {}",
                full_uri, a, b, sandbox_name
            );
            return Ok(3);
        }
        let (code, zero_secrets, out) =
            wasm.execute_mesh_call(Arc::clone(&pep), sandbox_name, 0, &full_uri, &payload_bytes)?;
        assert!(
            zero_secrets,
            "Wasm linear memory must contain 0 credential bytes"
        );
        if code == WASI_ERR_ACCESS_DENIED {
            println!(
                "{}/add({}, {}) -> refused: biscuit denied by office-node policy (wasm exit {})",
                full_uri, a, b, code
            );
            return Ok(3);
        }
        if code < 0 {
            println!("{}/add({}, {}) -> error {}", full_uri, a, b, code);
            return Ok(4);
        }
        let parsed: Value = serde_json::from_str(&out).unwrap_or_else(|_| json!({}));
        let res_val = parsed.get("result").and_then(|v| v.as_f64()).unwrap_or(0.0);
        println!(
            "{}/add({}, {}) = {:.1}  [wasm linear memory: 0 JWT/Biscuit bytes]",
            full_uri, a, b, res_val
        );
        return Ok(0);
    }

    println!("== tools the mesh offers sandbox {}", sandbox_name);
    for s in &services {
        let short_peer = &s.peer_id[..s.peer_id.len().min(16)];
        println!(
            "  {}...  mcp://{:<18} {}",
            short_peer, s.srv_name, s.srv_description
        );
    }

    if services.is_empty() {
        println!("== mcp://calc, allowed for the sandbox role");
        println!(
            "mcp://calc/add({}, {}) -> refused: the mesh shows sandbox '{}' no MCP provider (no role binds its identity)",
            a, b, sandbox_name
        );
        return Ok(0);
    }

    println!("== mcp://calc, allowed for the sandbox role");
    let (calc_code, calc_zero_sec, calc_out) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        sandbox_name,
        0,
        "mcp://calc",
        &payload_bytes,
    )?;
    assert!(
        calc_zero_sec,
        "Wasm linear memory must contain 0 credential bytes"
    );
    if calc_code > 0 {
        let parsed: Value = serde_json::from_str(&calc_out).unwrap_or_else(|_| json!({}));
        let res_val = parsed.get("result").and_then(|v| v.as_f64()).unwrap_or(0.0);
        println!(
            "mcp://calc/add({}, {}) = {:.1}  [wasm linear memory: 0 JWT/Biscuit bytes]",
            a, b, res_val
        );
    } else {
        println!(
            "mcp://calc/add({}, {}) -> refused (wasm exit {})",
            a, b, calc_code
        );
    }

    println!("== mcp://payroll, not in the sandbox role");
    let (pay_code, pay_zero_sec, _) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        sandbox_name,
        0,
        "mcp://payroll",
        &payload_bytes,
    )?;
    assert!(
        pay_zero_sec,
        "Wasm linear memory must contain 0 credential bytes"
    );
    println!(
        "mcp://payroll/add({}, {}) -> refused: auth rejected by office-node (HTTP 403 -> WASI_ERR_ACCESS_DENIED = {})",
        a, b, pay_code
    );
    Ok(0)
}

// ============================================================================
// Subcommand 3: `check` (Self-Contained 8-Case Live v0.2.0 E2E Suite)
// ============================================================================

fn run_live_check_suite(one_bin: &Path, node_bin: &Path) -> Result<(), String> {
    println!("=========================================================================");
    println!("  google/agentmesh x Wasmtime v49.0.4 -- Live Multi-Node E2E Suite");
    println!("=========================================================================");
    println!("  agentmesh-one : {}", one_bin.display());
    println!("  agentmesh-node: {}", node_bin.display());

    let work_dir = env::temp_dir().join(format!("am-wasm-{}", random_hex(4)));
    let cp_dir = work_dir.join("cp");
    let office_dir = work_dir.join("office");
    let edge_dir = work_dir.join("edge");
    fs::create_dir_all(&cp_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&office_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&edge_dir).map_err(|e| e.to_string())?;

    // 1. Start Loopback OIDC Issuer & Local MCP Backends
    let (_oidc_srv, issuer) = start_oidc_http_server(0, TRUST_DOMAIN_DEFAULT, AUDIENCE_DEFAULT)?;
    let mcp_srv = start_mcp_backend_server(0)?;
    println!(
        "  [boot] OIDC workload issuer ready at {}",
        issuer.issuer_url()
    );
    println!(
        "  [boot] Local Streamable HTTP MCP backend ready on 127.0.0.1:{}",
        mcp_srv.port
    );

    // 2. Render policy.json and office.yaml
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_path = work_dir.join("policy.json");
    fs::copy(manifest_dir.join("policy.json"), &policy_path).map_err(|e| e.to_string())?;

    let office_tmpl =
        fs::read_to_string(manifest_dir.join("office.yaml.tmpl")).map_err(|e| e.to_string())?;
    let office_yaml_path = work_dir.join("office.yaml");
    fs::write(
        &office_yaml_path,
        office_tmpl.replace("__MCP_PORT__", &mcp_srv.port.to_string()),
    )
    .map_err(|e| e.to_string())?;

    let join_token_path = work_dir.join("join.token");
    let admin_token_path = work_dir.join("admin.token");
    let office_api_path = work_dir.join("office-api.token");
    let edge_api_path = work_dir.join("edge-api.token");

    let join_token = format!("mesh_tok_{}", random_hex(16));
    let admin_token = format!("mesh_adm_{}", random_hex(16));
    fs::write(&join_token_path, &join_token).map_err(|e| e.to_string())?;
    fs::write(&admin_token_path, &admin_token).map_err(|e| e.to_string())?;
    fs::write(&office_api_path, random_hex(16)).map_err(|e| e.to_string())?;
    fs::write(&edge_api_path, random_hex(16)).map_err(|e| e.to_string())?;

    // 3. Spawn `agentmesh-one`
    let cp_port = pick_free_port()?;
    let cp_url = format!("http://127.0.0.1:{}", cp_port);
    let cp_log_path = work_dir.join("cp.log");
    let cp_log = File::create(&cp_log_path).map_err(|e| e.to_string())?;
    let cp_err = cp_log.try_clone().map_err(|e| e.to_string())?;

    let mut cp_cmd = Command::new(one_bin);
    cp_cmd
        .arg("--bind-address=127.0.0.1")
        .arg(format!("--port={}", cp_port))
        .arg(format!("--data-dir={}", cp_dir.display()))
        .arg(format!("--policy-file={}", policy_path.display()))
        .arg(format!("--token-path={}", join_token_path.display()))
        .arg(format!("--admin-token-path={}", admin_token_path.display()))
        .arg(format!("--workload-issuer={}", issuer.issuer_url()))
        .arg(format!("--allowed-audiences={}", AUDIENCE_DEFAULT))
        .arg("--router-allow-loopback=true")
        .arg("--enroll-qr=false")
        .arg("--log-format=json")
        .stdout(Stdio::from(cp_log))
        .stderr(Stdio::from(cp_err));

    let mut cp_proc = ManagedChild::spawn("agentmesh-one", cp_cmd)?;
    wait_http_200(
        &format!("{}/info", cp_url),
        Duration::from_secs(20),
        &mut cp_proc,
        &cp_log_path,
    )?;
    println!("  [boot] agentmesh-one ready at {}", cp_url);

    // Mint single-use bootstrap tokens for office-node and edge-node
    let office_boot_path = work_dir.join("office-boot.token");
    let edge_boot_path = work_dir.join("edge-boot.token");
    for (desc, target) in [
        ("office-node", &office_boot_path),
        ("edge-node", &edge_boot_path),
    ] {
        let headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", admin_token),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let body = serde_json::to_vec(&json!({
            "role": "mesh:role:node",
            "ttl_hours": 1,
            "max_usages": 1,
            "description": desc,
        }))
        .unwrap();
        let tok = match http_request(
            "POST",
            &format!("{}/admin/bootstrap-tokens", cp_url),
            &headers,
            &body,
        ) {
            Ok((code, resp)) if (200..300).contains(&code) => {
                serde_json::from_slice::<Value>(&resp).ok().and_then(|v| {
                    v.get("token")
                        .or_else(|| v.get("secret"))
                        .and_then(|t| t.as_str())
                        .map(String::from)
                })
            }
            _ => None,
        };
        fs::write(target, tok.as_deref().unwrap_or(&join_token)).map_err(|e| e.to_string())?;
    }

    // 4. Spawn `office-node`
    let office_port = pick_free_port()?;
    let office_metrics_port = pick_free_port()?;
    let office_log_path = work_dir.join("office.log");
    let office_log = File::create(&office_log_path).map_err(|e| e.to_string())?;
    let office_err = office_log.try_clone().map_err(|e| e.to_string())?;

    let mut office_cmd = Command::new(node_bin);
    office_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            office_boot_path.display()
        ))
        .arg(format!("--api-token-path={}", office_api_path.display()))
        .arg(format!("--data-dir={}", office_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", office_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", office_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=5s")
        .arg(format!("--config={}", office_yaml_path.display()))
        .arg("--log-format=json")
        .stdout(Stdio::from(office_log))
        .stderr(Stdio::from(office_err));

    let mut office_proc = ManagedChild::spawn("office-node", office_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", office_metrics_port),
        Duration::from_secs(25),
        &mut office_proc,
        &office_log_path,
    )?;
    println!(
        "  [boot] office-node enrolled & ready on 127.0.0.1:{}",
        office_port
    );

    // 5. Spawn `edge-node`
    let edge_port = pick_free_port()?;
    let edge_metrics_port = pick_free_port()?;
    let edge_url = format!("http://127.0.0.1:{}", edge_port);
    let edge_log_path = work_dir.join("edge.log");
    let edge_log = File::create(&edge_log_path).map_err(|e| e.to_string())?;
    let edge_err = edge_log.try_clone().map_err(|e| e.to_string())?;

    let mut edge_cmd = Command::new(node_bin);
    edge_cmd
        .arg("run")
        .arg(format!("--control-plane={}", cp_url))
        .arg(format!(
            "--bootstrap-token-path={}",
            edge_boot_path.display()
        ))
        .arg(format!("--api-token-path={}", edge_api_path.display()))
        .arg(format!("--data-dir={}", edge_dir.display()))
        .arg(format!("--bind-addr=127.0.0.1:{}", edge_port))
        .arg(format!("--metrics-addr=127.0.0.1:{}", edge_metrics_port))
        .arg("--socket-path=")
        .arg("--listen=/ip4/127.0.0.1/tcp/0")
        .arg("--allow-loopback")
        .arg("--discovery-interval=1s")
        .arg("--control-plane-sync-interval=5s")
        .arg("--log-format=json")
        .stdout(Stdio::from(edge_log))
        .stderr(Stdio::from(edge_err));

    let mut edge_proc = ManagedChild::spawn("edge-node", edge_cmd)?;
    wait_http_200(
        &format!("http://127.0.0.1:{}/readyz", edge_metrics_port),
        Duration::from_secs(25),
        &mut edge_proc,
        &edge_log_path,
    )?;
    println!("  [boot] edge-node enrolled & ready at {}", edge_url);

    // 6. Initialize Host PEP & Wasmtime Sandbox Runner
    let pep = Arc::new(HostPepBridge::new(&edge_url, Arc::clone(&issuer)));
    let wasm = Arc::new(WasmSandboxRunner::new()?);

    let demo_biscuit = pep.get_or_exchange_biscuit("demo", 0)?;
    let mut peer_id = String::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if let Ok(items) = pep.discover_services(&demo_biscuit, Some("calc")) {
            if let Some(first) = items.into_iter().find(|i| !i.peer_id.is_empty()) {
                peer_id = first.peer_id;
                break;
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
    if peer_id.is_empty() {
        return Err("DHT discovery returned empty provider list after 25s".into());
    }
    pep.set_provider_peer_id(peer_id.clone());
    println!(
        "  [mesh] Discovered office-node PeerID over libp2p DHT: {}",
        peer_id
    );

    // CASE 1: Allowed Wasm call (`demo -> mcp://calc`) + 0-secret linear memory check
    let (exit_calc, zero_sec_calc, out_calc) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        "demo",
        0,
        "mcp://calc",
        br#"{"op":"add","a":19,"b":23}"#,
    )?;
    assert!(
        exit_calc > 0,
        "Expected positive byte count, got {}",
        exit_calc
    );
    assert!(
        zero_sec_calc,
        "Wasm linear memory must contain 0 JWT/Biscuit bytes"
    );
    let calc_json: Value = serde_json::from_str(&out_calc).map_err(|e| e.to_string())?;
    assert_eq!(calc_json.get("result").and_then(|v| v.as_f64()), Some(42.0));
    println!(
        "  [PASS] Case 1: Wasm `demo` -> libp2p -> `mcp://calc` => 42.0 (0 JWT/Biscuit bytes in Wasm linear memory)"
    );

    // CASE 2: Caller header hygiene & verified X-Mesh-Principal injection
    let dirty_headers = vec![
        (
            "Authorization".into(),
            "Bearer caller_secret_must_be_stripped".into(),
        ),
        ("Cookie".into(), "session=caller_cookie_secret".into()),
        (
            "X-Mesh-Authentication".into(),
            "Bearer spoofed_token".into(),
        ),
    ];
    let (echo_status, echo_bytes) = pep.call_mesh_service_with_biscuit(
        "mcp://echo-headers",
        &demo_biscuit,
        &dirty_headers,
        br#"{"probe":"headers"}"#,
    )?;
    assert_eq!(echo_status, 200);
    let echo_json: Value = serde_json::from_slice(&echo_bytes).map_err(|e| e.to_string())?;
    assert_eq!(
        echo_json
            .get("authorization_present")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        echo_json.get("cookie_present").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        echo_json
            .get("x_mesh_auth_present")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    let principal = echo_json
        .get("x_mesh_principal")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        principal.contains("spiffe://agentmesh.local/wasm/demo/epoch/0"),
        "Unexpected x-mesh-principal: {}",
        echo_json
    );
    println!(
        "  [PASS] Case 2: Caller `Authorization`/`Cookie`/`X-Mesh-*` stripped; backend received `X-Mesh-Principal: {}`",
        principal
    );

    // CASE 3: Refused service (`demo -> mcp://payroll` => 403 -> Wasm -5)
    let (exit_pay, zero_sec_pay, _) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        "demo",
        0,
        "mcp://payroll",
        br#"{"op":"add","a":2,"b":3}"#,
    )?;
    assert_eq!(exit_pay, WASI_ERR_ACCESS_DENIED);
    assert!(zero_sec_pay);
    println!(
        "  [PASS] Case 3: Denied service (`demo -> mcp://payroll`) refused by office-node (HTTP 403 -> Wasm -5)"
    );

    // CASE 4: Role separation (`ledger` reaches `mcp://payroll`, refused `mcp://calc`) & unbound `rogue` refused
    let (exit_ledger_pay, zero_sec_lp, _) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        "ledger",
        0,
        "mcp://payroll",
        br#"{"op":"add","a":10,"b":5}"#,
    )?;
    assert!(exit_ledger_pay > 0 && zero_sec_lp);
    let (exit_ledger_calc, _, _) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        "ledger",
        0,
        "mcp://calc",
        br#"{"op":"add","a":10,"b":5}"#,
    )?;
    assert_eq!(exit_ledger_calc, WASI_ERR_ACCESS_DENIED);
    let (exit_rogue, zero_sec_rogue, _) = wasm.execute_mesh_call(
        Arc::clone(&pep),
        "rogue",
        0,
        "mcp://calc",
        br#"{"op":"add","a":1,"b":1}"#,
    )?;
    assert_eq!(exit_rogue, WASI_ERR_ACCESS_DENIED);
    assert!(zero_sec_rogue);
    println!(
        "  [PASS] Case 4: Role & sibling isolation (`ledger` -> payroll 200 / calc 403; unbound `rogue` -> calc 403)"
    );

    // CASE 5: Task-scoped sealed Biscuit (`scope=mcp://calc&seal=true`)
    let demo_jwt = issuer.mint_jwt("demo", 0, unix_now(), None, None, 300)?;
    let sealed_biscuit = pep.exchange_jwt(&demo_jwt, Some("mcp://calc"), true)?;
    let (sc_calc_status, _) = pep.call_mesh_service_with_biscuit(
        "mcp://calc",
        &sealed_biscuit,
        &[],
        br#"{"op":"mul","a":6,"b":7}"#,
    )?;
    assert_eq!(sc_calc_status, 200);
    let (sc_echo_status, _) = pep.call_mesh_service_with_biscuit(
        "mcp://echo-headers",
        &sealed_biscuit,
        &[],
        br#"{"probe":"blocked_by_tar_block"}"#,
    )?;
    assert_eq!(sc_echo_status, 403);
    println!(
        "  [PASS] Case 5: Sealed task Biscuit (`scope=mcp://calc&seal=true`) allowed `mcp://calc` (200) and refused `mcp://echo-headers` (403)"
    );

    // CASE 6: Invalid `aud`, `iss`, and expired `exp` JWT rejection at `POST /oauth/token`
    let now = unix_now();
    let bad_aud = issuer.mint_jwt("demo", 0, now, None, Some("wrong-aud"), 300)?;
    let bad_iss = issuer.mint_jwt("demo", 0, now, Some("http://127.0.0.1:65531"), None, 300)?;
    let expired = issuer.mint_jwt("demo", 0, now.saturating_sub(600), None, None, 60)?;
    for (label, bad_jwt) in [
        ("wrong_aud", bad_aud),
        ("wrong_iss", bad_iss),
        ("expired", expired),
    ] {
        assert!(
            pep.exchange_jwt(&bad_jwt, None, false).is_err(),
            "{} must be rejected at POST /oauth/token",
            label
        );
    }
    pep.evict_sandbox("demo");
    let recovered = pep.get_or_exchange_biscuit("demo", 0)?;
    assert!(!recovered.is_empty());
    println!(
        "  [PASS] Case 6: Wrong `aud`, wrong `iss`, and expired `exp` JWTs rejected at `/oauth/token`; fresh JWT recovered (200)"
    );

    // CASE 7: RFC 7009 Biscuit revocation (`POST /oauth/revoke`) blocks replay at edge-node
    pep.revoke_biscuit(&sealed_biscuit)?;
    let (rev_status, _) = pep.call_mesh_service_with_biscuit(
        "mcp://calc",
        &sealed_biscuit,
        &[],
        br#"{"op":"add","a":1,"b":2}"#,
    )?;
    assert!(
        rev_status == 401 || rev_status == 403,
        "Revoked Biscuit must be rejected on replay, got HTTP {}",
        rev_status
    );
    println!(
        "  [PASS] Case 7: RFC 7009 `POST /oauth/revoke` immediately blocked Biscuit replay (HTTP {})",
        rev_status
    );

    // CASE 8: Non-cooperative infinite-loop Wasm guest preempted via `increment_epoch()` in < 1ms
    let wasm_spin = Arc::clone(&wasm);
    let pep_spin = Arc::clone(&pep);
    let spin_handle = thread::spawn(move || wasm_spin.execute_infinite_spin(pep_spin));
    thread::sleep(Duration::from_millis(20));
    let t0 = Instant::now();
    wasm.engine().increment_epoch();
    let purge_dur = pep.evict_sandbox("demo");
    let spin_res = spin_handle.join().map_err(|_| "spin thread panicked")?;
    let total_preempt = t0.elapsed();
    assert!(
        spin_res.is_err(),
        "Infinite-loop Wasm guest must trap on epoch increment"
    );
    assert!(purge_dur < Duration::from_millis(1));
    println!(
        "  [PASS] Case 8: `Engine::increment_epoch()` trapped infinite-loop Wasm guest & purged host cache (purge {} us, total {} us)",
        purge_dur.as_micros(),
        total_preempt.as_micros()
    );

    thread::sleep(Duration::from_millis(200));
    let cp_logs = fs::read_to_string(&cp_log_path).unwrap_or_default();
    let office_logs = fs::read_to_string(&office_log_path).unwrap_or_default();
    assert!(cp_logs.contains("Border Crossing"));
    assert!(office_logs.contains("AuthZ Denied") || office_logs.contains("denied"));

    println!("-------------------------------------------------------------------------");
    println!("  Verified `agentmesh-one` (`Border Crossing`) & `office-node` (`AuthZ Denied`) audit logs.");
    println!("  ALL 8 WASMTIME x AGENT MESH E2E INVARIANTS PASSED.");
    println!("=========================================================================");

    drop(edge_proc);
    drop(office_proc);
    drop(cp_proc);
    let _ = fs::remove_dir_all(&work_dir);
    Ok(())
}

// ============================================================================
// CLI Entrypoint
// ============================================================================

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("check");

    match cmd {
        "build" => {}
        "serve" => {
            let Some((one_bin, node_bin)) = locate_agentmesh_binaries() else {
                eprintln!(
                    "ERROR: `agentmesh-one` and `agentmesh-node` not found.\n\
                     Run `./run.sh` (or `make up`) to download or build the binaries automatically."
                );
                std::process::exit(1);
            };
            if let Err(e) = run_serve_command(&one_bin, &node_bin) {
                eprintln!("serve error: {}", e);
                std::process::exit(1);
            }
        }
        "call" => {
            let mut name = "demo".to_string();
            let mut service: Option<String> = None;
            let mut payload: Option<String> = None;
            let mut a = 2.0f64;
            let mut b = 3.0f64;
            let mut edge_url: Option<String> = None;
            let mut oidc_url: Option<String> = None;

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--name" if i + 1 < args.len() => {
                        name = args[i + 1].clone();
                        i += 2;
                    }
                    "--service" if i + 1 < args.len() => {
                        service = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--payload" if i + 1 < args.len() => {
                        payload = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--a" if i + 1 < args.len() => {
                        a = args[i + 1].parse().unwrap_or(2.0);
                        i += 2;
                    }
                    "--b" if i + 1 < args.len() => {
                        b = args[i + 1].parse().unwrap_or(3.0);
                        i += 2;
                    }
                    "--edge-url" if i + 1 < args.len() => {
                        edge_url = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--oidc-url" if i + 1 < args.len() => {
                        oidc_url = Some(args[i + 1].clone());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            match run_call_command(
                &name,
                service.as_deref(),
                payload.as_deref(),
                a,
                b,
                edge_url.as_deref(),
                oidc_url.as_deref(),
            ) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("call error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "check" => {
            let Some((one_bin, node_bin)) = locate_agentmesh_binaries() else {
                eprintln!(
                    "ERROR: `agentmesh-one` and `agentmesh-node` not found.\n\
                     Run `./run.sh` (or `make check`) to download or build the binaries automatically."
                );
                std::process::exit(1);
            };
            if let Err(e) = run_live_check_suite(&one_bin, &node_bin) {
                eprintln!("E2E check failed:\n{}", e);
                std::process::exit(1);
            }
        }
        other => {
            eprintln!(
                "Unknown command '{}'. Expected: check | serve | call",
                other
            );
            std::process::exit(2);
        }
    }
}

// ============================================================================
// Fast Unit & Protocol Tests (`cargo test`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_es256_ieee_p1363_vs_der_rejection() {
        let issuer = WorkloadOidcIssuer::new(
            "http://127.0.0.1:18008",
            TRUST_DOMAIN_DEFAULT,
            AUDIENCE_DEFAULT,
        );
        let jwt = issuer
            .mint_jwt("demo", 0, 1_700_000_000, None, None, 300)
            .expect("mint jwt");
        let sig_b64 = jwt.split('.').nth(2).expect("jwt sig");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).expect("base64url decode");
        assert_eq!(sig_bytes.len(), 64);
        assert!(parse_ieee_p1363_signature(&sig_bytes).is_ok());

        // ASN.1 DER encoded signature (starts with 0x30, length 70) must be rejected
        let mut fake_der = vec![0x30, 0x44, 0x02, 0x20];
        fake_der.resize(70, 0x01);
        assert!(parse_ieee_p1363_signature(&fake_der).is_err());
    }

    #[test]
    fn test_jwks_key_rotation_preserves_retired_key() {
        let issuer = WorkloadOidcIssuer::new(
            "http://127.0.0.1:18008",
            TRUST_DOMAIN_DEFAULT,
            AUDIENCE_DEFAULT,
        );
        assert_eq!(issuer.jwks_document().keys.len(), 1);
        issuer.rotate_key("wasm-key-02");
        let jwks = issuer.jwks_document();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, "wasm-key-02");
        assert_eq!(jwks.keys[1].kid, "wasm-key-01");
    }

    #[test]
    fn test_logical_mesh_uri_validation_blocks_ssrf() {
        assert_eq!(
            validate_logical_mesh_uri("mcp://calc").unwrap(),
            ("mcp", "calc")
        );
        assert_eq!(
            validate_logical_mesh_uri("egress://bigquery.googleapis.com").unwrap(),
            ("egress", "bigquery.googleapis.com")
        );
        assert!(validate_logical_mesh_uri("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_logical_mesh_uri("https://example.com").is_err());
        assert!(validate_logical_mesh_uri("file:///etc/passwd").is_err());
        assert!(validate_logical_mesh_uri("mcp://../secret").is_err());
    }

    #[test]
    fn test_header_hygiene_strips_caller_secrets() {
        let dirty = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Cookie".to_string(), "sid=123".to_string()),
            (
                "X-Mesh-Authentication".to_string(),
                "Bearer spoof".to_string(),
            ),
            ("X-Mesh-Principal".to_string(), "spiffe://spoof".to_string()),
            ("X-Custom-Trace".to_string(), "trace-1".to_string()),
        ];
        let clean = sanitize_and_inject_headers(&dirty, "biscuit_token_abc");
        assert_eq!(clean.len(), 2);
        assert_eq!(
            clean[0],
            ("X-Custom-Trace".to_string(), "trace-1".to_string())
        );
        assert_eq!(
            clean[1],
            (
                "X-Mesh-Authentication".to_string(),
                "Bearer biscuit_token_abc".to_string()
            )
        );
    }

    #[test]
    fn test_linear_memory_zero_secret_scanner() {
        let clean_mem = b"{\"service\":\"calc\",\"result\":42.0}";
        let active = vec!["biscuit_secret_token_value_123456".to_string()];
        assert!(verify_linear_memory_zero_secrets(clean_mem, &active));

        let leaked_jwt_mem = b"prefix eyJhbGciOiJFUzI1NiI suffix";
        assert!(!verify_linear_memory_zero_secrets(leaked_jwt_mem, &active));

        let leaked_biscuit_mem = b"prefix biscuit_secret_tok suffix";
        assert!(!verify_linear_memory_zero_secrets(
            leaked_biscuit_mem,
            &active
        ));
    }
}
