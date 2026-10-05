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

import type { MessageInitShape } from "@bufbuild/protobuf";
import { toHex } from "./bytes.ts";
import { ControlPlaneClient, KeysNotTrustedError, ROLE_NODE, type Enrollment } from "./controlplane.ts";
import {
  attenuateCredential,
  credentialFromJSON,
  credentialPredatesRotation,
  credentialTimeToLiveSeconds,
  credentialToJSON,
  encodeAuthFrame,
  sealCredential,
  withCredentialMethods,
  type MeshCredential,
} from "./credential.ts";
import type { TaskAuthorizationRuleSchema } from "./gen/sam_pb.ts";
import { Identity } from "./identity.ts";
import { openState, readTextFile } from "./platform/state.ts";
import type { StateStore } from "./platform/types.ts";
import { joinMesh, type JoinOptions, type MeshSession } from "./session.ts";

const IDENTITY_FILE = "identity.key";
const CREDENTIAL_FILE = "credential.json";
/** A saved credential with less validity left than this is not worth resuming; enroll again instead. */
const REUSE_MIN_TTL_SECONDS = 5 * 60;

/**
 * The saved credential was issued under a signing key the control plane no
 * longer serves, so nothing can verify or refresh it; the member must enroll
 * again with a token.
 */
export class CredentialRetiredError extends Error {
  constructor(stateDir: string) {
    super(
      `the credential in ${stateDir} was issued under a key the control plane no longer serves ` +
        "(the member was off for longer than the key grace period); enroll again with a token",
    );
    this.name = "CredentialRetiredError";
  }
}

/**
 * The saved credential with the control plane's current keys adopted, or
 * undefined when the control plane vouches for none of the keys it trusts. A
 * control plane that cannot be reached, or answers in a way that is not a
 * verdict on the keys, leaves the credential as it is: the pull before join
 * tries again.
 */
async function resumableCredential(controlPlane: ControlPlaneClient, credential: MeshCredential): Promise<MeshCredential | undefined> {
  let keys: Uint8Array[];
  try {
    keys = await controlPlane.keys(credential.controlPlaneKeys);
  } catch (err) {
    return err instanceof KeysNotTrustedError ? undefined : credential;
  }
  if (keys.length === 0 || sameKeySet(keys, credential.controlPlaneKeys)) {
    return credential;
  }
  return { ...credential, controlPlaneKeys: keys };
}

export interface AgentMeshOptions {
  /** Base URL of the control plane, e.g. https://mesh.example.com. */
  controlPlaneUrl: string;
  /** Accept plaintext http:// to a non-loopback control plane. Off by default. */
  allowInsecure?: boolean;
  /**
   * Where the identity key and the credential are kept across restarts: a
   * directory on Node, an IndexedDB database of that name in a browser.
   * Without it the identity lives only in this process.
   */
  stateDir?: string | undefined;
  /** Use this identity instead of the persisted or a freshly generated one. */
  identity?: Identity;
  /** Role to enroll as. Defaults to ROLE_NODE. */
  role?: string;
  /** Operator-declared labels, e.g. { region: "eu" }. */
  labels?: Record<string, string>;
  /** Injection point for tests. */
  fetch?: typeof fetch;
}

/** Callback returning a fresh platform or OIDC JWT for enrollment and refresh. */
export type JwtSource = () => string | Promise<string>;

export interface EnrollOptions extends AgentMeshOptions {
  /** A bootstrap token value, when the caller already holds it in memory. */
  bootstrapToken?: string | undefined;
  /** Path of a file holding the bootstrap token. Preferred over a value on Node; a browser has no files. */
  bootstrapTokenPath?: string | undefined;
  /**
   * An OIDC ID token value, or a callback returning a fresh OIDC / platform
   * workload identity token at enrollment and on every refresh.
   */
  jwt?: string | JwtSource | undefined;
  /**
   * Path of a file holding an OIDC ID token or a platform's workload identity
   * token, such as a Kubernetes projected service account token. Preferred
   * over a value; the file is read at enrollment and on every refresh.
   */
  jwtPath?: string | undefined;
  /** Bounds the wait for an operator to approve a pending enrollment. */
  signal?: AbortSignal;
  /** Overrides the control plane's suggested poll interval while pending. */
  pollIntervalMs?: number;
}

/** What one pull from the control plane changed. */
export interface ControlPlaneSync {
  /** The trusted key set differs from before the pull. */
  keysChanged: boolean;
  /** The credential was re-issued because a rotation had happened since. */
  refreshed: boolean;
  /** The control plane's ban set, when /info answered. */
  bannedPeerIds: string[] | undefined;
  /** When /info was asked; a ban recorded later cannot be in the answer. */
  fetchedAt: Date;
  /** One entry per part that failed; empty when everything landed. */
  errors: string[];
}

/**
 * A member of the mesh: an identity, the credential the control plane minted
 * for it, and the client that keeps that credential fresh. join() puts it on
 * the mesh over libp2p.
 */
export class AgentMesh {
  readonly identity: Identity;
  readonly controlPlane: ControlPlaneClient;
  #credential: MeshCredential;
  readonly #state: StateStore | undefined;
  readonly #jwtSource: (() => Promise<string>) | undefined;

  private constructor(
    identity: Identity,
    controlPlane: ControlPlaneClient,
    credential: MeshCredential,
    state: StateStore | undefined,
    jwtSource?: (() => Promise<string>) | undefined,
  ) {
    this.identity = identity;
    this.controlPlane = controlPlane;
    this.#credential = withCredentialMethods(credential);
    this.#state = state;
    this.#jwtSource = jwtSource;
  }

  get peerId(): string {
    return this.identity.peerId;
  }

  get credential(): MeshCredential {
    return this.#credential;
  }

  /** Returns a new MeshCredential with a tar_block appended offline in memory. */
  attenuate(rule: MessageInitShape<typeof TaskAuthorizationRuleSchema>): Promise<MeshCredential> {
    return attenuateCredential(this.#credential, rule);
  }

  /** Returns a new MeshCredential with its biscuit sealed against further attenuation. */
  seal(): Promise<MeshCredential> {
    return sealCredential(this.#credential);
  }

  /**
   * Enrolls with the control plane and returns a member holding a credential.
   *
   * When stateDir already holds an unexpired credential from this control
   * plane for the saved identity, that member is returned and no token is
   * needed, so a program can call enroll on every start and read the token
   * from its environment only on the first. A credential is resumed only
   * while the control plane still serves a key the member trusts: one issued
   * under a key that retired while the member was off cannot be verified or
   * refreshed, so the member enrolls again with the token given, or throws
   * CredentialRetiredError without one. Otherwise exactly one of
   * bootstrapToken, bootstrapTokenPath, jwt or jwtPath must be given. Delete
   * the state directory to enroll afresh, for instance with other labels.
   */
  static async enroll(options: EnrollOptions): Promise<AgentMesh> {
    const state = options.stateDir !== undefined ? openState(options.stateDir) : undefined;
    const saved = await loadIdentity(state);
    const identity = options.identity ?? saved ?? Identity.generate();
    const controlPlane = newClient(options);
    const jwtSource = resolveJwtSource(options);
    const given = [options.bootstrapToken, options.bootstrapTokenPath, options.jwt, options.jwtPath].filter((v) => v !== undefined).length;
    if (state !== undefined && saved !== undefined && saved.peerId === identity.peerId) {
      const credential = await loadCredential(state);
      if (credential !== undefined && sameBaseUrl(credential.controlPlaneUrl, controlPlane.url) && credentialTimeToLiveSeconds(credential) > REUSE_MIN_TTL_SECONDS) {
        const resumed = await resumableCredential(controlPlane, credential);
        if (resumed !== undefined) {
          const mesh = new AgentMesh(identity, controlPlane, resumed, state, jwtSource);
          if (resumed !== credential) {
            await mesh.save();
          }
          return mesh;
        }
        if (given === 0) {
          throw new CredentialRetiredError(options.stateDir as string);
        }
      }
    }
    if (given !== 1) {
      const where = options.stateDir !== undefined ? ` (no credential to resume in ${options.stateDir})` : "";
      throw new Error(`exactly one of bootstrapToken, bootstrapTokenPath, jwt or jwtPath is required${where}`);
    }
    const role = options.role ?? ROLE_NODE;

    let enrollment: Enrollment;
    if (options.jwt !== undefined || options.jwtPath !== undefined) {
      const jwt = jwtSource !== undefined ? await jwtSource() : (options.jwt as string);
      enrollment = await controlPlane.register({ identity, jwt, role, ...labelsOf(options) });
    } else {
      const bootstrapToken = options.bootstrapTokenPath !== undefined ? (await readTextFile(options.bootstrapTokenPath)).trim() : (options.bootstrapToken as string);
      enrollment = await controlPlane.enrollBootstrap({
        identity,
        bootstrapToken,
        role,
        ...labelsOf(options),
        ...(options.pollIntervalMs !== undefined ? { pollIntervalMs: options.pollIntervalMs } : {}),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      });
    }

    // Widen trust from the one key the enrollment carries to every key the
    // control plane currently signs with, so peers holding credentials from
    // a retiring key still verify. Best effort, as in sam-node.
    let controlPlaneKeys = [enrollment.controlPlanePublicKey];
    try {
      controlPlaneKeys = await controlPlane.keys(controlPlaneKeys);
    } catch {
      // The enrollment key alone still works until the next sync.
    }

    const mesh = new AgentMesh(
      identity,
      controlPlane,
      {
        controlPlaneUrl: baseUrl(controlPlane.url),
        biscuit: enrollment.biscuit,
        expiration: enrollment.expiration,
        controlPlaneKeys,
        issuedUnderKeys: controlPlaneKeys,
        routerAddresses: enrollment.routerAddresses,
      },
      state,
      jwtSource,
    );
    await mesh.save();
    return mesh;
  }

  /**
   * Resumes a member from a state directory written by an earlier enroll(),
   * for a process that must never hold an enrollment token. The control
   * plane URL comes from the saved credential.
   */
  static async load(
    options: Omit<AgentMeshOptions, "controlPlaneUrl"> & {
      stateDir: string;
      jwt?: JwtSource | undefined;
      jwtPath?: string | undefined;
    },
  ): Promise<AgentMesh> {
    const state = openState(options.stateDir);
    const identity = options.identity ?? (await loadIdentity(state));
    if (!identity) {
      throw new Error(`no identity in ${options.stateDir}; enroll first`);
    }
    const credential = await loadCredential(state);
    if (credential === undefined) {
      throw new Error(`no credential in ${options.stateDir}; enroll first`);
    }
    return new AgentMesh(
      identity,
      newClient({ ...options, controlPlaneUrl: credential.controlPlaneUrl }),
      credential,
      state,
      resolveJwtSource(options),
    );
  }

  /**
   * Trades the current biscuit for a fresh one and persists it. The control
   * plane redeems only the last biscuit it issued, so a lost refresh result
   * means re-enrolling; persisting before returning keeps that rare.
   */
  async refresh(): Promise<MeshCredential> {
    let jwt: string | undefined;
    if (this.#jwtSource !== undefined) {
      try {
        const token = await this.#jwtSource();
        if (token !== "") {
          jwt = token;
        }
      } catch {
        // Best effort: fall back to session-only refresh if the token source is temporarily unavailable.
      }
    }
    const result = await this.controlPlane.refresh({
      identity: this.identity,
      biscuit: this.#credential.biscuit,
      ...(jwt !== undefined ? { jwt } : {}),
    });
    let controlPlaneKeys = this.#credential.controlPlaneKeys;
    try {
      controlPlaneKeys = await this.controlPlane.keys(controlPlaneKeys);
    } catch {
      // Keep the previous set; a failed /keys sync must not cost the new biscuit.
    }
    this.#credential = withCredentialMethods({
      ...this.#credential,
      biscuit: result.biscuit,
      expiration: result.expiration,
      controlPlaneKeys,
      issuedUnderKeys: controlPlaneKeys,
    });
    await this.save();
    return this.#credential;
  }

  /**
   * Adopts a signing key announced by a KEY_ROTATION event, so peers whose
   * credentials the new key signs verify before the next pull confirms it.
   */
  addTrustedKey(key: Uint8Array): boolean {
    const hex = toHex(key);
    if (this.#credential.controlPlaneKeys.some((k) => toHex(k) === hex)) {
      return false;
    }
    this.#credential = withCredentialMethods({ ...this.#credential, controlPlaneKeys: [...this.#credential.controlPlaneKeys, key] });
    return true;
  }

  /**
   * The member's pull from the control plane, as sam-node's SyncControlPlane:
   * the signing keys (verified against the set already trusted, so whoever
   * answers the URL cannot become the trust root), a credential refresh when
   * a rotation happened since it was issued, and /info for the router
   * addresses and the ban set. Each part is attempted even when another
   * fails; the errors are reported together. Gossip events only bring this
   * forward; they are never the only way state arrives.
   */
  async syncControlPlane(): Promise<ControlPlaneSync> {
    const errors: string[] = [];
    let keysChanged = false;
    let refreshed = false;
    try {
      const keys = await this.controlPlane.keys(this.#credential.controlPlaneKeys);
      if (keys.length === 0) {
        throw new Error("/keys returned no keys");
      }
      keysChanged = !sameKeySet(keys, this.#credential.controlPlaneKeys);
      this.#credential = withCredentialMethods({ ...this.#credential, controlPlaneKeys: keys });
      if (credentialPredatesRotation(this.#credential)) {
        await this.refresh();
        refreshed = true;
      }
    } catch (err) {
      errors.push(`keys: ${err instanceof Error ? err.message : String(err)}`);
    }

    let bannedPeerIds: string[] | undefined;
    // Taken before the request: a ban recorded after this instant cannot be
    // in the answer, so its absence must not be read as an unban.
    const fetchedAt = new Date();
    try {
      const info = await this.controlPlane.info();
      if (info.routerAddresses.length > 0) {
        this.#credential = withCredentialMethods({ ...this.#credential, routerAddresses: info.routerAddresses });
      }
      bannedPeerIds = info.bannedPeerIds;
    } catch (err) {
      errors.push(`info: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (keysChanged || bannedPeerIds !== undefined) {
      await this.save();
    }
    return { keysChanged, refreshed, bannedPeerIds, fetchedAt, errors };
  }

  /**
   * The frame that opens every stream to a peer: this member's biscuit plus
   * the service it wants (e.g. "mcp://calculator").
   */
  authFrame(targetService = ""): Uint8Array {
    return encodeAuthFrame(this.#credential.biscuit, targetService);
  }

  /**
   * Joins the mesh: connects to the routers in the credential, passes the
   * auth handshake with them, reserves a relay slot and keeps the credential
   * fresh for as long as the session is open.
   */
  join(options?: JoinOptions): Promise<MeshSession> {
    return joinMesh(this, options);
  }

  /** Writes identity and credential to the state store, if one is configured. */
  async save(): Promise<void> {
    if (this.#state === undefined) {
      return;
    }
    await this.#state.write(IDENTITY_FILE, this.identity.toLibp2pPrivateKey());
    await this.#state.write(CREDENTIAL_FILE, new TextEncoder().encode(credentialToJSON(this.#credential)));
  }
}

function newClient(options: AgentMeshOptions): ControlPlaneClient {
  return new ControlPlaneClient({
    url: options.controlPlaneUrl,
    allowInsecure: options.allowInsecure ?? false,
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
  });
}

function sameKeySet(a: Uint8Array[], b: Uint8Array[]): boolean {
  const hex = (keys: Uint8Array[]) =>
    keys
      .map((k) => toHex(k))
      .sort()
      .join(",");
  return hex(a) === hex(b);
}

function labelsOf(options: AgentMeshOptions): { labels?: Record<string, string> } {
  return options.labels !== undefined ? { labels: options.labels } : {};
}

async function loadIdentity(state: StateStore | undefined): Promise<Identity | undefined> {
  const bytes = await state?.read(IDENTITY_FILE);
  return bytes === undefined ? undefined : Identity.fromLibp2pPrivateKey(bytes);
}

async function loadCredential(state: StateStore): Promise<MeshCredential | undefined> {
  const bytes = await state.read(CREDENTIAL_FILE);
  return bytes === undefined ? undefined : credentialFromJSON(new TextDecoder().decode(bytes));
}

/** The form every implementation persists: scheme, host, port, path, no trailing slash. */
function baseUrl(url: URL | string): string {
  return String(url).replace(/\/+$/, "");
}

function sameBaseUrl(a: URL | string, b: URL | string): boolean {
  return baseUrl(a) === baseUrl(b);
}

function resolveJwtSource(options: { jwt?: string | JwtSource | undefined; jwtPath?: string | undefined }): (() => Promise<string>) | undefined {
  if (options.jwtPath !== undefined) {
    const path = options.jwtPath;
    return async () => (await readTextFile(path)).trim();
  }
  if (typeof options.jwt === "function") {
    const fn = options.jwt;
    return async () => (await fn()).trim();
  }
  return undefined;
}

