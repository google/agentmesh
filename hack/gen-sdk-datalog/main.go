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

// Command gen-sdk-datalog writes the baseline Datalog a mesh member evaluates
// when it authorizes a caller, as api/datalog.go and api/tar.go define it,
// into the JSON/TS artifacts the native SDKs embed, and generates the
// deterministic cross-language TAR conformance vectors in
// sdk/testdata/tar_conformance.json. Go stays the source of truth;
// hack/verify-sdk-generated.sh fails when the artifacts are stale.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type artifact struct {
	Comment string `json:"_comment"`
	api.DatalogSources
	FactNode                string   `json:"fact_node"`
	FactClientPeer          string   `json:"fact_client_peer_id"`
	FactActorNode           string   `json:"fact_actor_node"`
	FactService             string   `json:"fact_service"`
	FactConnectionPeer      string   `json:"fact_connection_peer_id"`
	FactMethod              string   `json:"fact_method"`
	FactPath                string   `json:"fact_path"`
	FactTime                string   `json:"fact_time"`
	FactRole                string   `json:"fact_role"`
	FactTargetFact          string   `json:"fact_target_fact"`
	FactTARBlock            string   `json:"fact_tar_block"`
	TARBlockSourcePattern   string   `json:"tar_block_source_pattern"`
	HTTPMethodSyntax        string   `json:"http_method_syntax"`
	MaxAttenuationBlocks    int      `json:"max_attenuation_blocks"`
	MaxTARBytes             int      `json:"max_tar_bytes"`
	MaxRulesPerTAR          int      `json:"max_rules_per_tar"`
	MaxEntriesPerTARList    int      `json:"max_entries_per_tar_list"`
	MaxTARNameLength        int      `json:"max_tar_name_length"`
	MaxTARDescriptionLength int      `json:"max_tar_description_length"`
	MaxTARResourceLength    int      `json:"max_tar_resource_length"`
	MarkerTerm              string   `json:"marker_term"`
	SystemNamespace         string   `json:"system_namespace"`
	BindingPrefixes         []string `json:"binding_member_prefixes"`
	SystemAuthenticated     string   `json:"system_authenticated_member"`
}

type tarConformanceSuite struct {
	Comment            string                 `json:"_comment"`
	PublicKeyB64       string                 `json:"public_key_b64"`
	CallerPeerID       string                 `json:"caller_peer_id"`
	ProviderPeerID     string                 `json:"provider_peer_id"`
	ProviderBiscuitB64 string                 `json:"provider_biscuit_b64"`
	EvaluationTime     string                 `json:"evaluation_time"`
	PolicyDatalogRules []string               `json:"policy_datalog_rules"`
	Vectors            []tarConformanceVector `json:"vectors"`
}

type tarConformanceVector struct {
	Name                        string  `json:"name"`
	BiscuitB64                  string  `json:"biscuit_b64"`
	TargetService               string  `json:"target_service"`
	Protocol                    string  `json:"protocol"`
	Method                      *string `json:"method,omitempty"`
	Path                        string  `json:"path,omitempty"`
	MCPTool                     string  `json:"mcp_tool,omitempty"`
	Allow                       bool    `json:"allow"`
	ExpectedEffectiveExpiration string  `json:"expected_effective_expiration,omitempty"`
}

// deterministicReader is a reproducible stream of bytes derived from SHA-256
// blocks so Biscuit keypair generation and sealing are 100% deterministic.
type deterministicReader struct {
	seed    string
	counter uint64
	buf     []byte
}

func newDeterministicReader(seed string) io.Reader {
	return &deterministicReader{seed: seed}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		if len(d.buf) == 0 {
			var ctr [8]byte
			binary.LittleEndian.PutUint64(ctr[:], d.counter)
			d.counter++
			h := sha256.New()
			h.Write([]byte(d.seed))
			h.Write(ctr[:])
			d.buf = h.Sum(nil)
		}
		n := copy(p[written:], d.buf)
		d.buf = d.buf[n:]
		written += n
	}
	return written, nil
}

func deterministicPeerID(seed string) peer.ID {
	sum := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	libp2pPriv, err := crypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	pid, err := peer.IDFromPrivateKey(libp2pPriv)
	if err != nil {
		panic(err)
	}
	return pid
}

func strPtr(s string) *string { return &s }

func buildConformanceSuite() tarConformanceSuite {
	cpSeed := sha256.Sum256([]byte("sam-tar-conformance-cp-root-key-v1"))
	cpPriv := ed25519.NewKeyFromSeed(cpSeed[:])
	cpPub := cpPriv.Public().(ed25519.PublicKey)

	callerPeer := deterministicPeerID("sam-tar-conformance-caller-peer-v1")
	providerPeer := deterministicPeerID("sam-tar-conformance-provider-peer-v1")

	evalTime := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	authExp := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	hop1Exp := time.Date(2034, 6, 1, 0, 0, 0, 0, time.UTC)
	hop2Exp := time.Date(2034, 3, 1, 0, 0, 0, 0, time.UTC)
	expiredExp := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// Mint provider Biscuit.
	provBuilder := biscuit.NewBuilder(cpPriv, biscuit.WithRandom(newDeterministicReader("provider-root")))
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(providerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(providerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(authExp)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
	} {
		if err := provBuilder.AddAuthorityFact(f); err != nil {
			panic(err)
		}
	}
	provToken, err := provBuilder.Build()
	if err != nil {
		panic(err)
	}
	provBytes, err := provToken.Serialize()
	if err != nil {
		panic(err)
	}

	// Mint caller authority Biscuit with wildcard service and target grants.
	callerBuilder := biscuit.NewBuilder(cpPriv, biscuit.WithRandom(newDeterministicReader("caller-root")))
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(callerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(callerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(authExp)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		api.MarkerFact(api.FactGrantedServiceAllTypes),
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := callerBuilder.AddAuthorityFact(f); err != nil {
			panic(err)
		}
	}
	callerRoot, err := callerBuilder.Build()
	if err != nil {
		panic(err)
	}
	callerRootBytes, err := callerRoot.Serialize()
	if err != nil {
		panic(err)
	}

	hop1 := &api.TaskAuthorizationRule{
		Name:        "orchestrator-hop",
		DisplayName: "Orchestrator Task Scope",
		ExpireTime:  timestamppb.New(hop1Exp),
		Rules: []*api.TaskRule{
			{
				Description:     "Weather MCP tools",
				AllowedServices: []string{"mcp://weather"},
				Operation: &api.TaskOperation{
					AllowedTools: []string{"get_weather", "get_forecast"},
				},
			},
			{
				Description:     "GitHub API read/write under /repos/acme/*",
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &api.TaskOperation{
					AllowedMethods: []string{"GET", "POST"},
					AllowedPaths:   []string{"/repos/acme/*"},
				},
			},
			{
				Description:     "Gemini inference prefix",
				AllowedServices: []string{"inference://gemini.*"},
			},
		},
	}
	att1Bytes, err := identity.AttenuateBiscuitWithRand(newDeterministicReader("hop1"), callerRootBytes, hop1)
	if err != nil {
		panic(err)
	}

	hop2 := &api.TaskAuthorizationRule{
		Name:        "subagent-hop",
		DisplayName: "Subagent Narrowed Scope",
		ExpireTime:  timestamppb.New(hop2Exp),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation: &api.TaskOperation{
					AllowedTools: []string{"get_weather"},
				},
			},
			{
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &api.TaskOperation{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/repos/acme/public/*"},
				},
			},
		},
	}
	att2Bytes, err := identity.AttenuateBiscuitWithRand(newDeterministicReader("hop2"), att1Bytes, hop2)
	if err != nil {
		panic(err)
	}
	sealedAtt2Bytes, err := identity.SealBiscuitWithRand(newDeterministicReader("seal-hop2"), att2Bytes)
	if err != nil {
		panic(err)
	}

	expiredRule := &api.TaskAuthorizationRule{
		Name:       "expired-hop",
		ExpireTime: timestamppb.New(expiredExp),
		Rules:      []*api.TaskRule{{AllowedServices: []string{"*"}}},
	}
	expiredBytes, err := identity.AttenuateBiscuitWithRand(newDeterministicReader("expired"), callerRootBytes, expiredRule)
	if err != nil {
		panic(err)
	}

	// Empty rules TAR block (valid protobuf, 0 rules -> fail-closed deny).
	emptyTARRaw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&api.TaskAuthorizationRule{Name: "empty-rules"})
	if err != nil {
		panic(err)
	}
	emptyTARFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.String(base64.RawURLEncoding.EncodeToString(emptyTARRaw))},
	}}
	bbEmpty := callerRoot.CreateBlock()
	_ = bbEmpty.AddFact(emptyTARFact)
	bEmpty, err := callerRoot.Append(newDeterministicReader("empty-rules"), bbEmpty.Build())
	if err != nil {
		panic(err)
	}
	emptyRulesBytes, _ := bEmpty.Serialize()

	// 9 blocks (> MaxAttenuationBlocks).
	cur9 := callerRootBytes
	for i := 0; i < api.MaxAttenuationBlocks; i++ {
		cur9, err = identity.AttenuateBiscuitWithRand(newDeterministicReader(fmt.Sprintf("b9-%d", i)), cur9, hop1)
		if err != nil {
			panic(err)
		}
	}
	b8, _ := biscuit.Unmarshal(cur9)
	validFact, _ := api.EncodeTARBlockFact(hop1)
	bb9 := b8.CreateBlock()
	_ = bb9.AddFact(validFact)
	b9, _ := b8.Append(newDeterministicReader("b9-9"), bb9.Build())
	nineBlocksBytes, _ := b9.Serialize()

	// Block with rule.
	bbRule := callerRoot.CreateBlock()
	_ = bbRule.AddFact(validFact)
	r, _ := parser.FromStringRule(`x($a) <- tar_block($a)`)
	_ = bbRule.AddRule(r)
	bWithRule, _ := callerRoot.Append(newDeterministicReader("with-rule"), bbRule.Build())
	withRuleBytes, _ := bWithRule.Serialize()

	// Block with check.
	bbCheck := callerRoot.CreateBlock()
	_ = bbCheck.AddFact(validFact)
	chk, _ := parser.FromStringCheck(`check if tar_block($a)`)
	_ = bbCheck.AddCheck(chk)
	bWithCheck, _ := callerRoot.Append(newDeterministicReader("with-check"), bbCheck.Build())
	withCheckBytes, _ := bWithCheck.Serialize()

	// Block with two facts.
	bbTwoFacts := callerRoot.CreateBlock()
	_ = bbTwoFacts.AddFact(validFact)
	_ = bbTwoFacts.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.String("extra")},
	}})
	bTwoFacts, _ := callerRoot.Append(newDeterministicReader("two-facts"), bbTwoFacts.Build())
	twoFactsBytes, _ := bTwoFacts.Serialize()

	// Block with wrong predicate name (e.g. node("attacker")).
	bbWrongPred := callerRoot.CreateBlock()
	_ = bbWrongPred.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(providerPeer.String())},
	}})
	bWrongPred, _ := callerRoot.Append(newDeterministicReader("wrong-pred"), bbWrongPred.Build())
	wrongPredBytes, _ := bWrongPred.Serialize()

	// Block with bytes term instead of string.
	bbBytesTerm := callerRoot.CreateBlock()
	_ = bbBytesTerm.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.Bytes([]byte{1, 2, 3})},
	}})
	bBytesTerm, _ := callerRoot.Append(newDeterministicReader("bytes-term"), bbBytesTerm.Build())
	bytesTermBytes, _ := bBytesTerm.Serialize()

	// Block with unknown protobuf wire field in tar_block.
	hop1Raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(hop1)
	unknownRaw := protowire.AppendTag(hop1Raw, 99, protowire.VarintType)
	unknownRaw = protowire.AppendVarint(unknownRaw, 1)
	bbUnknownProto := callerRoot.CreateBlock()
	_ = bbUnknownProto.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.String(base64.RawURLEncoding.EncodeToString(unknownRaw))},
	}})
	bUnknownProto, _ := callerRoot.Append(newDeterministicReader("unknown-proto"), bbUnknownProto.Build())
	unknownProtoBytes, _ := bUnknownProto.Serialize()

	b64 := base64.StdEncoding.EncodeToString

	return tarConformanceSuite{
		Comment:            "Generated by hack/gen-sdk-datalog; do not edit.",
		PublicKeyB64:       b64(cpPub),
		CallerPeerID:       callerPeer.String(),
		ProviderPeerID:     providerPeer.String(),
		ProviderBiscuitB64: b64(provBytes),
		EvaluationTime:     evalTime.Format(time.RFC3339),
		PolicyDatalogRules: []string{},
		Vectors: []tarConformanceVector{
			{
				Name:                        "authority_only_allowed",
				BiscuitB64:                  b64(callerRootBytes),
				TargetService:               "mcp://weather",
				Protocol:                    string(api.MCPProtocolID),
				MCPTool:                     "any_tool",
				Allow:                       true,
				ExpectedEffectiveExpiration: authExp.Format(time.RFC3339),
			},
			{
				Name:                        "one_hop_mcp_allowed_tool",
				BiscuitB64:                  b64(att1Bytes),
				TargetService:               "mcp://weather",
				Protocol:                    string(api.MCPProtocolID),
				MCPTool:                     "get_forecast",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop1Exp.Format(time.RFC3339),
			},
			{
				Name:          "one_hop_mcp_denied_tool",
				BiscuitB64:    b64(att1Bytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "drop_table",
				Allow:         false,
			},
			{
				Name:          "one_hop_mcp_missing_tool_denied_on_http",
				BiscuitB64:    b64(att1Bytes),
				TargetService: "mcp://weather",
				Protocol:      "/libp2p-http",
				Method:        strPtr("POST"),
				Path:          "/mcp",
				Allow:         false,
			},
			{
				Name:                        "one_hop_wildcard_prefix_inference_allowed",
				BiscuitB64:                  b64(att1Bytes),
				TargetService:               "inference://gemini.pro",
				Protocol:                    "/libp2p-http",
				Method:                      strPtr("POST"),
				Path:                        "/v1/chat/completions",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop1Exp.Format(time.RFC3339),
			},
			{
				Name:          "one_hop_dot_boundary_inference_denied",
				BiscuitB64:    b64(att1Bytes),
				TargetService: "inference://gemini2.pro",
				Protocol:      "/libp2p-http",
				Method:        strPtr("POST"),
				Path:          "/v1/chat/completions",
				Allow:         false,
			},
			{
				Name:                        "two_hop_intersection_mcp_allowed",
				BiscuitB64:                  b64(att2Bytes),
				TargetService:               "mcp://weather",
				Protocol:                    string(api.MCPProtocolID),
				MCPTool:                     "get_weather",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop2Exp.Format(time.RFC3339),
			},
			{
				Name:          "two_hop_intersection_mcp_dropped_tool_denied",
				BiscuitB64:    b64(att2Bytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_forecast",
				Allow:         false,
			},
			{
				Name:                        "two_hop_intersection_http_allowed",
				BiscuitB64:                  b64(att2Bytes),
				TargetService:               "egress://api.github.com",
				Protocol:                    "/libp2p-http",
				Method:                      strPtr("GET"),
				Path:                        "/repos/acme/public/readme",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop2Exp.Format(time.RFC3339),
			},
			{
				Name:          "two_hop_intersection_http_dropped_method_denied",
				BiscuitB64:    b64(att2Bytes),
				TargetService: "egress://api.github.com",
				Protocol:      "/libp2p-http",
				Method:        strPtr("POST"),
				Path:          "/repos/acme/public/readme",
				Allow:         false,
			},
			{
				Name:          "two_hop_intersection_http_dropped_path_denied",
				BiscuitB64:    b64(att2Bytes),
				TargetService: "egress://api.github.com",
				Protocol:      "/libp2p-http",
				Method:        strPtr("GET"),
				Path:          "/repos/acme/private/secret",
				Allow:         false,
			},
			{
				Name:          "two_hop_intersection_connect_tunnel_denied",
				BiscuitB64:    b64(att2Bytes),
				TargetService: "egress://api.github.com",
				Protocol:      "/libp2p-http",
				Method:        strPtr("CONNECT"),
				Path:          "",
				Allow:         false,
			},
			{
				Name:                        "sealed_two_hop_allowed",
				BiscuitB64:                  b64(sealedAtt2Bytes),
				TargetService:               "egress://api.github.com",
				Protocol:                    "/libp2p-http",
				Method:                      strPtr("GET"),
				Path:                        "/repos/acme/public/readme",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop2Exp.Format(time.RFC3339),
			},
			{
				Name:          "expired_tar_block_rejected",
				BiscuitB64:    b64(expiredBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "empty_rules_tar_denied",
				BiscuitB64:    b64(emptyRulesBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "nine_blocks_rejected",
				BiscuitB64:    b64(nineBlocksBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_rule_rejected",
				BiscuitB64:    b64(withRuleBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_check_rejected",
				BiscuitB64:    b64(withCheckBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_two_facts_rejected",
				BiscuitB64:    b64(twoFactsBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_wrong_predicate_rejected",
				BiscuitB64:    b64(wrongPredBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_bytes_term_rejected",
				BiscuitB64:    b64(bytesTermBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name:          "block_with_unknown_proto_field_rejected",
				BiscuitB64:    b64(unknownProtoBytes),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
			{
				Name: "delegated_token_no_node_fact_allowed",
				BiscuitB64: b64(func() []byte {
					policyRoles := []*api.PolicyRole{
						{
							Name:            "analyst",
							AllowedServices: []string{"*"},
							AllowedTargets:  []string{"*"},
						},
					}
					tok, err := identity.MintDelegatedBiscuitTokenWithRand(
						newDeterministicReader("delegated-caller"),
						cpPriv,
						map[string]any{"sub": "alice", "email": "alice@example.com"},
						callerPeer,
						authExp,
						[]string{"analyst"},
						policyRoles,
						hop1,
						true,
					)
					if err != nil {
						panic(err)
					}
					return tok
				}()),
				TargetService:               "mcp://weather",
				Protocol:                    string(api.MCPProtocolID),
				MCPTool:                     "get_weather",
				Allow:                       true,
				ExpectedEffectiveExpiration: hop1Exp.Format(time.RFC3339),
			},
			{
				Name: "delegated_token_wrong_actor_rejected",
				BiscuitB64: b64(func() []byte {
					policyRoles := []*api.PolicyRole{
						{
							Name:            "analyst",
							AllowedServices: []string{"*"},
							AllowedTargets:  []string{"*"},
						},
					}
					tok, err := identity.MintDelegatedBiscuitTokenWithRand(
						newDeterministicReader("delegated-wrong-actor"),
						cpPriv,
						map[string]any{"sub": "alice", "email": "alice@example.com"},
						providerPeer,
						authExp,
						[]string{"analyst"},
						policyRoles,
						hop1,
						false,
					)
					if err != nil {
						panic(err)
					}
					return tok
				}()),
				TargetService: "mcp://weather",
				Protocol:      string(api.MCPProtocolID),
				MCPTool:       "get_weather",
				Allow:         false,
			},
		},
	}
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: gen-sdk-datalog <output.json> <output.ts> [conformance.json]")
		os.Exit(2)
	}
	a := artifact{
		Comment:                 "Generated by hack/gen-sdk-datalog from api/datalog.go; do not edit.",
		DatalogSources:          api.BaselineSources,
		FactNode:                api.FactNode,
		FactClientPeer:          api.FactClientPeerID,
		FactActorNode:           api.FactActorNode,
		FactService:             api.FactService,
		FactConnectionPeer:      api.FactConnectionPeerID,
		FactMethod:              api.FactMethod,
		FactPath:                api.FactPath,
		FactTime:                api.FactTime,
		FactRole:                api.FactRole,
		FactTargetFact:          api.FactTargetFact,
		FactTARBlock:            api.FactTARBlock,
		TARBlockSourcePattern:   api.TARBlockSourcePattern,
		HTTPMethodSyntax:        api.HTTPMethodSyntaxPattern(),
		MaxAttenuationBlocks:    api.MaxAttenuationBlocks,
		MaxTARBytes:             api.MaxTARBytes,
		MaxRulesPerTAR:          api.MaxRulesPerTAR,
		MaxEntriesPerTARList:    api.MaxEntriesPerTARList,
		MaxTARNameLength:        api.MaxTARNameLength,
		MaxTARDescriptionLength: api.MaxTARDescriptionLength,
		MaxTARResourceLength:    api.MaxTARResourceLength,
		MarkerTerm:              api.MarkerTerm.String(),
		SystemNamespace:         api.SystemNamespace,
		BindingPrefixes:         api.BindingMemberPrefixes(),
		SystemAuthenticated:     api.SystemAuthenticated,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], buf.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ts := "// Code generated by hack/gen-sdk-datalog from api/datalog.go; DO NOT EDIT.\n\n" +
		"/** The Datalog a provider evaluates against a caller's biscuit. */\n" +
		"export const BASELINE_DATALOG = " + strings.TrimRight(buf.String(), "\n") + " as const;\n"
	if err := os.WriteFile(os.Args[2], []byte(ts), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(os.Args) == 4 {
		suite := buildConformanceSuite()
		var cbuf bytes.Buffer
		cenc := json.NewEncoder(&cbuf)
		cenc.SetEscapeHTML(false)
		cenc.SetIndent("", "  ")
		if err := cenc.Encode(suite); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.MkdirAll(filepath.Dir(os.Args[3]), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(os.Args[3], cbuf.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
