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

package api

const (
	// SystemAuthenticated is a special member string representing any authenticated user.
	SystemAuthenticated = "mesh:system:authenticated"
)

type IngressConfig struct {
	// AuthMode is "edge" (default when empty) or "passthrough".
	AuthMode string `yaml:"auth_mode,omitempty"`
	// Allow optionally narrows which verified callers may invoke this service
	// over edge ingress, using PolicyBinding.members syntax (e.g.
	// "email:alice@example.com", "email:*@example.com", "group:eng").
	Allow []string `yaml:"allow,omitempty"`
}

type ServiceConfig struct {
	Type        string `yaml:"type"` // e.g., "mcp", "inference", "a2a"
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	TargetURL   string `yaml:"target_url,omitempty"`
	// TargetAuthPath names a file holding the credential the backend at
	// TargetURL requires: "TOKEN" is sent as "Authorization: Bearer TOKEN",
	// "user:pass" as HTTP Basic. A file, not a value, for the same reason
	// the CLI takes --api-token-path: config files are copied, committed and
	// rendered into ConfigMaps; a credential in one is a credential in all.
	TargetAuthPath string            `yaml:"target_auth_path,omitempty"`
	Command        []string          `yaml:"command,omitempty"`
	Env            map[string]string `yaml:"env,omitempty"`
	Ingress        *IngressConfig    `yaml:"ingress,omitempty"`
}

// NodeConfig defines the optional attenuation rules and static services for a specific Agent Mesh Node.
type NodeConfig struct {
	Version     string          `yaml:"version"`
	Attenuation Attenuation     `yaml:"attenuation"`
	Services    []ServiceConfig `yaml:"services"`
	// Labels is what this node is, attested at enrollment; Egress is what it
	// demands of the peers it talks to. Adjacent because they are read
	// together and mean opposite directions.
	Labels map[string]string `yaml:"labels,omitempty"`
	Egress Egress            `yaml:"egress"`
}

// NodeConfigVersionV1Alpha1 is the only node config schema this build understands.
// A file omitting the version is read as this one, since it predates the check.
const NodeConfigVersionV1Alpha1 = "v1alpha1"

// SupportedNodeConfigVersions gates LoadNodeConfig. A node must refuse a schema
// it does not know rather than parse it as this one: silently reinterpreting a
// future config would silently reinterpret its attenuation rules. Adding a
// version means adding it here and decoding it into the same internal type, so
// the rest of the node stays version-agnostic.
var SupportedNodeConfigVersions = map[string]bool{
	"":                        true,
	NodeConfigVersionV1Alpha1: true,
}

type Attenuation struct {
	Policies []string `yaml:"policies"`
	Checks   []string `yaml:"checks"`
	Rules    []string `yaml:"rules"`
}

// Egress is the operator's outbound policy: what this node demands of the peers
// it talks to. Attenuation is the mirror of it — what this node demands of the
// peers that talk to *it* — and the two are deliberately separate blocks
// because they answer opposite questions.
type Egress struct {
	// RequireLabels is a floor every remote provider must attest before this
	// node will send it anything, whatever the caller asked for. Absent means
	// no floor, which is the historical behaviour: the requirement is then
	// whatever the caller supplied, and a caller that supplies nothing is
	// unconstrained.
	//
	// Every pair must hold, as for a caller's requirement (see LabelCheck). A
	// map gives one value per key, so a floor cannot express alternatives —
	// that is the point: a floor with alternatives would let the weakest of
	// them stand in for the rest.
	//
	// A floor naming a label no peer attests reaches nothing, which is a
	// usable egress kill switch.
	RequireLabels map[string]string `yaml:"require_labels,omitempty"`
}
