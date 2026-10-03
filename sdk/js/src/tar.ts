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

import { create, fromBinary, toBinary, type MessageInitShape } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { fromBase64Url, toBase64Url } from "./bytes.ts";
import { isServiceType } from "./discovery.ts";
import { BASELINE_DATALOG } from "./gen/datalog.ts";
import { TaskAuthorizationRuleSchema, type TaskAuthorizationRule, type TaskRule } from "./gen/sam_pb.ts";

const TAR_BLOCK_SOURCE_RE = new RegExp(BASELINE_DATALOG.tar_block_source_pattern);
const HTTP_METHOD_RE = new RegExp(BASELINE_DATALOG.http_method_syntax);
const TEXT_ENCODER = new TextEncoder();

function utf8Length(s: string): number {
  return TEXT_ENCODER.encode(s).length;
}

function countChar(s: string, ch: string): number {
  let count = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === ch) {
      count++;
    }
  }
  return count;
}

export function validateServicePattern(s: string): void {
  if (s === "*") {
    return;
  }
  const idx = s.indexOf("://");
  if (idx <= 0) {
    throw new Error(`invalid service format: ${s}`);
  }
  const serviceType = s.slice(0, idx);
  const target = s.slice(idx + 3);
  if (!isServiceType(serviceType) && serviceType !== "http") {
    throw new Error(`invalid service type "${serviceType}" in ${s}`);
  }
  if (target === "" || target.includes("/") || countChar(target, "*") > 1) {
    throw new Error(`invalid service target "${target}" in ${s}`);
  }
  if (target.includes("*") && target !== "*") {
    const validSuffix = target.startsWith("*.") && target.slice(2).length > 0;
    const validPrefix = target.endsWith(".*") && target.slice(0, -2).length > 0;
    if (!validSuffix && !validPrefix) {
      throw new Error(`wildcard in "${s}" must be '*', '*.<suffix>' or '<prefix>.*'`);
    }
  }
}

export function validateHTTPGrantPath(p: string): void {
  if (!p.startsWith("/")) {
    throw new Error(`path ${JSON.stringify(p)} must start with '/'`);
  }
  if (p.includes("?") || p.includes("#")) {
    throw new Error(`path ${JSON.stringify(p)} must not contain '?' or '#'`);
  }
  const stars = countChar(p, "*");
  if (stars > 1 || (stars === 1 && !p.endsWith("*"))) {
    throw new Error(`path ${JSON.stringify(p)}: '*' is only valid once, at the end`);
  }
  for (const seg of p.slice(1).split("/")) {
    if (seg === "." || seg === "..") {
      throw new Error(`path ${JSON.stringify(p)} must not contain '.' or '..' segments`);
    }
  }
}

function validateTARStringList(fieldName: string, values: string[], checkElem: (v: string) => void): void {
  if (values.length > BASELINE_DATALOG.max_entries_per_tar_list) {
    throw new Error(`TaskRule.${fieldName} has ${values.length} entries; maximum is ${BASELINE_DATALOG.max_entries_per_tar_list}`);
  }
  for (const [i, val] of values.entries()) {
    try {
      checkElem(val);
    } catch (err) {
      throw new Error(`TaskRule.${fieldName}[${i}]: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

export function validateTaskRule(r: TaskRule): void {
  if (utf8Length(r.description) > BASELINE_DATALOG.max_tar_description_length) {
    throw new Error(`TaskRule.description exceeds ${BASELINE_DATALOG.max_tar_description_length} bytes`);
  }
  validateTARStringList("allowed_services", r.allowedServices, validateServicePattern);
  validateTARStringList("allowed_resources", r.allowedResources, (res) => {
    if (res === "") {
      throw new Error("resource must not be empty");
    }
    if (utf8Length(res) > BASELINE_DATALOG.max_tar_resource_length) {
      throw new Error(`resource exceeds ${BASELINE_DATALOG.max_tar_resource_length} bytes`);
    }
  });
  if (r.operation !== undefined) {
    const op = r.operation;
    validateTARStringList("operation.allowed_tools", op.allowedTools, (tool) => {
      if (tool === "") {
        throw new Error("tool name must not be empty");
      }
    });
    validateTARStringList("operation.allowed_methods", op.allowedMethods, (m) => {
      if (!HTTP_METHOD_RE.test(m)) {
        throw new Error(`invalid HTTP method ${JSON.stringify(m)}`);
      }
      if (m === "CONNECT") {
        throw new Error("CONNECT is not a grantable HTTP method");
      }
    });
    validateTARStringList("operation.allowed_paths", op.allowedPaths, validateHTTPGrantPath);
    validateTARStringList("operation.allowed_permissions", op.allowedPermissions, (perm) => {
      if (perm === "") {
        throw new Error("permission must not be empty");
      }
    });
  }
}

export function validateTaskAuthorizationRule(rule: TaskAuthorizationRule, requireNonEmptyRules: boolean): void {
  if (utf8Length(rule.name) > BASELINE_DATALOG.max_tar_name_length) {
    throw new Error(`TaskAuthorizationRule.name exceeds ${BASELINE_DATALOG.max_tar_name_length} bytes`);
  }
  if (utf8Length(rule.displayName) > BASELINE_DATALOG.max_tar_description_length) {
    throw new Error(`TaskAuthorizationRule.display_name exceeds ${BASELINE_DATALOG.max_tar_description_length} bytes`);
  }
  if (requireNonEmptyRules && rule.rules.length === 0) {
    throw new Error("TaskAuthorizationRule.rules must not be empty");
  }
  if (rule.rules.length > BASELINE_DATALOG.max_rules_per_tar) {
    throw new Error(`TaskAuthorizationRule.rules has ${rule.rules.length} entries; maximum is ${BASELINE_DATALOG.max_rules_per_tar}`);
  }
  for (const [i, r] of rule.rules.entries()) {
    try {
      validateTaskRule(r);
    } catch (err) {
      throw new Error(`TaskAuthorizationRule.rules[${i}]: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

function hasUnknownWireFields(rule: TaskAuthorizationRule): boolean {
  const unknownOf = (msg: unknown): boolean => {
    if (typeof msg !== "object" || msg === null) {
      return false;
    }
    const unk = (msg as { $unknown?: unknown[] }).$unknown;
    return Array.isArray(unk) && unk.length > 0;
  };
  if (unknownOf(rule) || unknownOf(rule.expireTime)) {
    return true;
  }
  for (const r of rule.rules) {
    if (unknownOf(r) || unknownOf(r.operation)) {
      return true;
    }
  }
  return false;
}

export function encodeTARBlockPayload(ruleInput: MessageInitShape<typeof TaskAuthorizationRuleSchema>): string {
  const rule = create(TaskAuthorizationRuleSchema, ruleInput);
  validateTaskAuthorizationRule(rule, true);
  const raw = toBinary(TaskAuthorizationRuleSchema, rule);
  if (raw.length > BASELINE_DATALOG.max_tar_bytes) {
    throw new Error(`TaskAuthorizationRule serialized size ${raw.length} exceeds ${BASELINE_DATALOG.max_tar_bytes} bytes`);
  }
  return toBase64Url(raw);
}

export function encodeTARBlockFact(ruleInput: MessageInitShape<typeof TaskAuthorizationRuleSchema>): string {
  const b64 = encodeTARBlockPayload(ruleInput);
  return `${BASELINE_DATALOG.fact_tar_block}(${JSON.stringify(b64)})`;
}

export function decodeTARBlockPayload(b64Payload: string): TaskAuthorizationRule {
  if (b64Payload === "") {
    throw new Error("empty tar_block payload");
  }
  let raw: Uint8Array;
  try {
    raw = fromBase64Url(b64Payload);
  } catch (err) {
    throw new Error(`invalid base64url in tar_block: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (toBase64Url(raw) !== b64Payload) {
    throw new Error("non-canonical base64url in tar_block");
  }
  if (raw.length === 0 || raw.length > BASELINE_DATALOG.max_tar_bytes) {
    throw new Error(`tar_block decoded payload size ${raw.length} out of bounds [1, ${BASELINE_DATALOG.max_tar_bytes}]`);
  }
  let rule: TaskAuthorizationRule;
  try {
    rule = fromBinary(TaskAuthorizationRuleSchema, raw);
  } catch (err) {
    throw new Error(`invalid TaskAuthorizationRule protobuf in tar_block: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (hasUnknownWireFields(rule)) {
    throw new Error("TaskAuthorizationRule in tar_block contains unknown protobuf wire fields");
  }
  validateTaskAuthorizationRule(rule, false);
  return rule;
}

export function parseTARBlockSource(blockSource: string): TaskAuthorizationRule {
  const m = TAR_BLOCK_SOURCE_RE.exec(blockSource.trim());
  if (!m || m[1] === undefined) {
    throw new Error(`non-authority block does not match single tar_block("<base64url>") grammar`);
  }
  return decodeTARBlockPayload(m[1]);
}

export function effectiveTARExpiration(authorityExpiration: Date, rules: TaskAuthorizationRule[]): Date {
  let effective = authorityExpiration;
  for (const r of rules) {
    if (r.expireTime !== undefined) {
      const exp = timestampDate(r.expireTime);
      if (exp.getTime() < effective.getTime()) {
        effective = exp;
      }
    }
  }
  return effective;
}

export interface TaskRequestContext {
  serviceType: string;
  serviceName: string;
  hasHttp: boolean;
  method: string;
  path: string;
  mcpTool: string;
  allowMCPStreamInit: boolean;
  resource?: string;
  permission?: string;
}

export function matchServicePattern(pattern: string, serviceType: string, serviceName: string): boolean {
  if (serviceType === "" || serviceName === "") {
    return false;
  }
  if (pattern === "*") {
    return true;
  }
  const idx = pattern.indexOf("://");
  if (idx <= 0) {
    return false;
  }
  const patType = pattern.slice(0, idx);
  const patTarget = pattern.slice(idx + 3);
  if (patType !== serviceType) {
    return false;
  }
  if (patTarget === "*") {
    return true;
  }
  if (patTarget.startsWith("*.")) {
    return serviceName.endsWith(patTarget.slice(1));
  }
  if (patTarget.endsWith(".*")) {
    return serviceName.startsWith(patTarget.slice(0, -1));
  }
  return serviceName === patTarget;
}

export function matchHTTPPath(pattern: string, reqPath: string): boolean {
  if (reqPath === "") {
    return false;
  }
  if (pattern.endsWith("*")) {
    return reqPath.startsWith(pattern.slice(0, -1));
  }
  return reqPath === pattern;
}

export function matchTaskRule(rule: TaskRule, req: TaskRequestContext): boolean {
  if (rule.allowedServices.length > 0) {
    if (!rule.allowedServices.some((pat) => matchServicePattern(pat, req.serviceType, req.serviceName))) {
      return false;
    }
  }
  if (rule.allowedResources.length > 0) {
    const res = req.resource ?? "";
    if (res === "" || !rule.allowedResources.includes(res)) {
      return false;
    }
  }
  if (rule.operation !== undefined) {
    const op = rule.operation;
    if (op.allowedTools.length > 0) {
      if (req.serviceType !== "mcp") {
        return false;
      }
      if (req.mcpTool === "") {
        if (!req.allowMCPStreamInit) {
          return false;
        }
      } else if (!op.allowedTools.includes(req.mcpTool)) {
        return false;
      }
    }
    if (op.allowedMethods.length > 0) {
      if (!req.hasHttp || req.method === "" || req.method === "CONNECT") {
        return false;
      }
      if (!op.allowedMethods.includes(req.method)) {
        return false;
      }
    }
    if (op.allowedPaths.length > 0) {
      if (!req.hasHttp || req.path === "" || req.method === "CONNECT") {
        return false;
      }
      if (!op.allowedPaths.some((pat) => matchHTTPPath(pat, req.path))) {
        return false;
      }
    }
    if (op.allowedPermissions.length > 0) {
      const perm = req.permission ?? "";
      if (perm === "" || !op.allowedPermissions.includes(perm)) {
        return false;
      }
    }
  }
  return true;
}

export function evaluateTaskRules(chain: TaskAuthorizationRule[], req: TaskRequestContext, now: Date): void {
  for (const [i, tar] of chain.entries()) {
    if (tar.expireTime !== undefined) {
      const exp = timestampDate(tar.expireTime);
      if (now.getTime() > exp.getTime()) {
        throw new Error(`TaskAuthorizationRule block ${i + 1} (${JSON.stringify(tar.name)}) is expired`);
      }
    }
    if (tar.rules.length === 0) {
      throw new Error(`TaskAuthorizationRule block ${i + 1} (${JSON.stringify(tar.name)}) has no rules (fail-closed)`);
    }
    if (!tar.rules.some((rule) => matchTaskRule(rule, req))) {
      throw new Error(`request denied by TaskAuthorizationRule block ${i + 1} (${JSON.stringify(tar.name)})`);
    }
  }
}
