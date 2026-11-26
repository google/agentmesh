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

package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/golang-jwt/jwt/v5"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	kb "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
)

// newDirectoryRouter is a router with its DHT and the directory handler
// up, as Start wires them, on a loopback host.
func newDirectoryRouter(t *testing.T) *Router {
	t.Helper()
	r, gated := newGatedRouter(t)
	r.gated = gated
	kdht, err := dht.New(gated, r.dhtOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kdht.Close() })
	r.DHT = kdht
	r.records = newRecordStore(r.directory.RecordTTL)
	gated.SetStreamHandler(api.DirectoryProtocolID, r.handleDirectory)
	return r
}

// held is the providers router r holds under key.
func held(r *Router, key []byte) []peer.AddrInfo {
	return r.records.providers(key, time.Now())
}

// federate connects two routers and has each admit the other as an
// authenticated peer router, as the handshake does.
func federate(t *testing.T, a, b *Router) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*Router{{a, b}, {b, a}} {
		pair[0].authenticatedPeers.Store(pair[1].Host.ID(), time.Now().Add(time.Hour))
		pair[0].admitPeerRouter(pair[1].Host.ID())
	}
}

// attach connects a member host to a router and marks it authenticated
// there, holding a credential that grants publishing the given services
// (allowed_publish syntax), as the handshake would have recorded.
func attach(t *testing.T, r *Router, publish ...string) host.Host {
	t.Helper()
	m := newClient(t, r)
	r.authenticatedPeers.Store(m.ID(), time.Now().Add(time.Hour))
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	role := &api.PolicyRole{Name: "member", AllowedPublish: publish}
	tok, _, err := identity.MintBiscuitToken(priv, jwt.MapClaims{"sub": "member"}, nil, m.ID(), time.Now().Add(time.Hour), []string{"member"}, []*api.PolicyRole{role}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := biscuit.Unmarshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	r.credentials.Store(m.ID(), memberCredential{biscuit: b, key: pub})
	return m
}

// ask sends one request to a router and returns its answer.
func ask(t *testing.T, from host.Host, router peer.ID, req *api.DirectoryRequest) *api.DirectoryResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := from.NewStream(ctx, router, api.DirectoryProtocolID)
	if err != nil {
		t.Fatalf("open directory stream: %v", err)
	}
	defer func() { _ = s.Close() }()
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(data); err != nil {
		t.Fatal(err)
	}
	frame, err := msgio.NewVarintReaderSize(s, directoryMaxMessage).ReadMsg()
	if err != nil {
		t.Fatalf("read directory answer: %v", err)
	}
	var resp api.DirectoryResponse
	if err := proto.Unmarshal(frame, &resp); err != nil {
		t.Fatal(err)
	}
	return &resp
}

// provide is a member's record for service under key; a service of ""
// is the member's own record under its peer key.
func provide(key []byte, service string, addrs ...string) *api.DirectoryRequest {
	return &api.DirectoryRequest{Request: &api.DirectoryRequest_Provide{Provide: &api.DirectoryProvide{Key: key, Service: service, Addrs: addrs}}}
}

func findProviders(key []byte) *api.DirectoryRequest {
	return &api.DirectoryRequest{Request: &api.DirectoryRequest_FindProviders{FindProviders: &api.DirectoryFindProviders{Key: key}}}
}

func findPeer(p peer.ID) *api.DirectoryRequest {
	return &api.DirectoryRequest{Request: &api.DirectoryRequest_FindPeer{FindPeer: &api.DirectoryFindPeer{PeerId: p.String()}}}
}

func directoryCount(t *testing.T, op, result string) float64 {
	t.Helper()
	var m dto.Metric
	if err := directoryRequestsTotal.WithLabelValues(op, result).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// A member announces a record to the router it is attached to; the router
// keeps it and places it on the routers closest to the key, as many as the
// mesh's replication. A member attached to any router then finds it: from
// that router's own records when it holds a copy, from the routers closest
// to the key otherwise. A peer is found the same way, under its peer key,
// or from the router that holds it.
func TestDirectoryRecordsAreFoundFromAnyRouter(t *testing.T) {
	a, b, c := newDirectoryRouter(t), newDirectoryRouter(t), newDirectoryRouter(t)
	federate(t, a, b)
	federate(t, a, c)
	federate(t, b, c)
	// One copy besides the member's own router, on the closest of the others.
	a.directory.Replication = 1

	member := attach(t, a, "mcp://calculator")
	key, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calculator")
	if err != nil {
		t.Fatal(err)
	}
	memberAddr := member.Addrs()[0].String() + "/p2p/" + member.ID().String()
	if resp := ask(t, member, a.Host.ID(), provide(key, "mcp://calculator", memberAddr)); resp.GetError() != "" {
		t.Fatalf("provide refused: %s", resp.GetError())
	}
	if resp := ask(t, member, a.Host.ID(), provide(api.PeerKey(member.ID()), "", memberAddr)); resp.GetError() != "" {
		t.Fatalf("provide of the peer key refused: %s", resp.GetError())
	}

	closest := a.DHT.RoutingTable().NearestPeers(kb.ConvertKey(string(key)), 1)
	if len(closest) != 1 {
		t.Fatalf("closest routers to the key = %v, want one", closest)
	}
	holder, other := b, c
	if closest[0] == c.Host.ID() {
		holder, other = c, b
	}
	if provs := held(holder, key); len(provs) != 1 || provs[0].ID != member.ID() {
		t.Fatalf("the closest router holds %v, want the member's record", provs)
	}
	if provs := held(other, key); len(provs) != 0 {
		t.Fatalf("the other router holds %v, want nothing: replication is one", provs)
	}

	for name, router := range map[string]*Router{"own router": a, "holder": holder, "other router, asking the closest": other} {
		t.Run("find providers from the "+name, func(t *testing.T) {
			asker := attach(t, router)
			resp := ask(t, asker, router.Host.ID(), findProviders(key))
			if resp.GetError() != "" {
				t.Fatalf("find_providers failed: %s", resp.GetError())
			}
			if len(resp.GetProviders()) != 1 || resp.GetProviders()[0].GetPeerId() != member.ID().String() {
				t.Fatalf("providers = %v, want the member", resp.GetProviders())
			}
			if got := resp.GetProviders()[0].GetAddrs(); !slices.Contains(got, memberAddr) {
				t.Fatalf("provider addrs = %v, want %s among them", got, memberAddr)
			}
		})
	}

	t.Run("find peer from the other router", func(t *testing.T) {
		asker := attach(t, other)
		resp := ask(t, asker, other.Host.ID(), findPeer(member.ID()))
		if resp.GetError() != "" {
			t.Fatalf("find_peer failed: %s", resp.GetError())
		}
		if resp.GetPeer().GetPeerId() != member.ID().String() || !slices.Contains(resp.GetPeer().GetAddrs(), memberAddr) {
			t.Fatalf("peer = %v, want the member at %s", resp.GetPeer(), memberAddr)
		}
	})

	t.Run("find peer from its own router answers from the connection", func(t *testing.T) {
		asker := attach(t, a)
		resp := ask(t, asker, a.Host.ID(), findPeer(member.ID()))
		if resp.GetPeer().GetPeerId() != member.ID().String() || len(resp.GetPeer().GetAddrs()) == 0 {
			t.Fatalf("peer = %v, want the member with addresses", resp.GetPeer())
		}
	})

	t.Run("nobody is found under a key nobody announced", func(t *testing.T) {
		before := directoryCount(t, directoryOpFindProviders, directoryResultEmpty)
		unknown, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "nobody")
		asker := attach(t, b)
		resp := ask(t, asker, b.Host.ID(), findProviders(unknown))
		if resp.GetError() != "" || len(resp.GetProviders()) != 0 {
			t.Fatalf("got %v, want an empty answer and no error", resp)
		}
		if got := directoryCount(t, directoryOpFindProviders, directoryResultEmpty); got != before+1 {
			t.Fatalf("empty answers counted = %v, want %v", got, before+1)
		}
		if resp := ask(t, asker, b.Host.ID(), findPeer(asker.ID())); resp.GetPeer() != nil && len(resp.GetPeer().GetAddrs()) == 0 {
			t.Fatalf("find_peer of a peer with no record = %v, want unset or its own connection", resp.GetPeer())
		}
	})
}

// A member can only announce itself and the services it names: a record
// naming another provider, an address of another peer, a key that is not
// a sha256 multihash, or a key that is not the named service's (nor the
// member's own peer key when no service is named) is refused and counted
// as invalid, and nothing is stored.
func TestDirectoryRefusesWhatAMemberMayNotAnnounce(t *testing.T) {
	a := newDirectoryRouter(t)
	member := attach(t, a, "mcp://*")
	stranger := newClient(t, a)
	key, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calculator")

	for name, req := range map[string]*api.DirectoryRequest{
		"another provider":                      {Request: &api.DirectoryRequest_Provide{Provide: &api.DirectoryProvide{Key: key, Provider: stranger.ID().String()}}},
		"another peer's address":                provide(key, "mcp://calculator", stranger.Addrs()[0].String()+"/p2p/"+stranger.ID().String()),
		"a key that is not a multihash":         provide([]byte("calculator"), "mcp://calculator"),
		"a key that is not the named service's": provide(key, "mcp://weather"),
		"a service key naming no service":       provide(key, ""),
		"a peer key naming a service":           provide(api.PeerKey(member.ID()), "mcp://calculator"),
		"another peer's key":                    provide(api.PeerKey(stranger.ID()), ""),
		"an address longer than the bound":      provide(key, "mcp://calculator", "/ip4/10.0.0.1/tcp/4001/tls/http/http-path/"+strings.Repeat("a", api.DirectoryMaxAddrBytes)),
		"a lookup of such a key":                findProviders([]byte("calculator")),
		"a peer id that is not one":             findPeer(peer.ID("nobody")),
	} {
		t.Run(name, func(t *testing.T) {
			op := directoryOpProvide
			switch req.GetRequest().(type) {
			case *api.DirectoryRequest_FindProviders:
				op = directoryOpFindProviders
			case *api.DirectoryRequest_FindPeer:
				op = directoryOpFindPeer
			}
			if req.GetProvide().GetProvider() != "" {
				op = directoryOpPlace
			}
			before := directoryCount(t, op, directoryResultInvalid)
			resp := ask(t, member, a.Host.ID(), req)
			if resp.GetError() == "" {
				t.Fatalf("accepted; want a refusal")
			}
			if got := directoryCount(t, op, directoryResultInvalid); got != before+1 {
				t.Fatalf("invalid %s counted = %v, want %v", op, got, before+1)
			}
		})
	}
	if provs := held(a, key); len(provs) != 0 {
		t.Fatalf("a refused record was stored: %v", provs)
	}
}

// A record placed by a router names its provider; the receiving router
// stores it under that provider, so a lookup there returns the member and
// not the router that placed it.
func TestDirectoryPlacementNamesTheProvider(t *testing.T) {
	a, b := newDirectoryRouter(t), newDirectoryRouter(t)
	federate(t, a, b)
	member := attach(t, a, "inference://llm")
	key, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_INFERENCE, "")
	memberAddr := member.Addrs()[0].String() + "/p2p/" + member.ID().String()
	if resp := ask(t, member, a.Host.ID(), provide(key, "inference://llm", memberAddr)); resp.GetError() != "" {
		t.Fatalf("provide refused: %s", resp.GetError())
	}
	provs := held(b, key)
	if len(provs) != 1 || provs[0].ID != member.ID() {
		t.Fatalf("router b holds %v, want the member's record placed by router a", provs)
	}
	if len(provs[0].Addrs) == 0 || provs[0].Addrs[0].String() != member.Addrs()[0].String() {
		t.Fatalf("router b holds addrs %v, want the member's %v without the peer suffix", provs[0].Addrs, member.Addrs()[0])
	}
}

func withdraw(key []byte) *api.DirectoryRequest {
	return &api.DirectoryRequest{Request: &api.DirectoryRequest_Withdraw{Withdraw: &api.DirectoryWithdraw{Key: key}}}
}

// newPeerID is the ID of a new Ed25519 key, the kind a member has.
func newPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}
	return id
}

// recordAddrBase starts an address that a test makes as long as it needs.
const recordAddrBase = "/ip4/203.0.113.7/tcp/443/tls/http/http-path/"

// addrOfBytes is address i of a record: n bytes, with no peer suffix.
func addrOfBytes(i, n int) string {
	return fmt.Sprintf("%s%02d%s", recordAddrBase, i, strings.Repeat("a", n-len(recordAddrBase)-2))
}

// An address of a record is at most api.DirectoryMaxAddrBytes with the
// provider's peer suffix, whether the member sent the suffix or not. An
// address at the bound is still accepted in the form an answer carries,
// which is the form a peer router reads.
func TestRecordAddrsBoundsAnAddress(t *testing.T) {
	provider := newPeerID(t)
	suffix := "/p2p/" + provider.String()
	atBound := addrOfBytes(0, api.DirectoryMaxAddrBytes-len(suffix))
	aboveBound := addrOfBytes(0, api.DirectoryMaxAddrBytes-len(suffix)+1)
	for name, tc := range map[string]struct {
		addr    string
		wantErr bool
	}{
		"at the bound, sent without the suffix":   {addr: atBound},
		"at the bound, sent with the suffix":      {addr: atBound + suffix},
		"one byte above, sent without the suffix": {addr: aboveBound, wantErr: true},
		"one byte above, sent with the suffix":    {addr: aboveBound + suffix, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			addrs, err := recordAddrs(provider, []string{tc.addr})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("recordAddrs accepted an address of %d bytes with its suffix, want a refusal above %d", len(aboveBound+suffix), api.DirectoryMaxAddrBytes)
				}
				if strings.Contains(err.Error(), recordAddrBase) {
					t.Errorf("the refusal repeats the address, want its length only: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("recordAddrs refused an address of %d bytes with its suffix, want it accepted up to %d: %v", len(atBound+suffix), api.DirectoryMaxAddrBytes, err)
			}
			rendered := peerRecord(peer.AddrInfo{ID: provider, Addrs: addrs}).GetAddrs()
			if _, err := recordAddrs(provider, rendered); err != nil {
				t.Errorf("recordAddrs refused the address as an answer carries it, %d bytes: %v", len(rendered[0]), err)
			}
		})
	}
}

// providerWith is a new provider with n addresses. Each address has
// addrBytes with the peer suffix that an answer adds.
func providerWith(t *testing.T, n, addrBytes int) peer.AddrInfo {
	t.Helper()
	info := peer.AddrInfo{ID: newPeerID(t)}
	for i := range n {
		addr, err := multiaddr.NewMultiaddr(addrOfBytes(i, addrBytes-len("/p2p/"+info.ID.String())))
		if err != nil {
			t.Fatalf("NewMultiaddr: %v", err)
		}
		info.Addrs = append(info.Addrs, addr)
	}
	return info
}

// oversizeAddrBytes makes a record of api.DirectoryMaxAddrs addresses
// larger than the frame, as the record of GHSA-gw5v-gc33-3wg6 was.
const oversizeAddrBytes = 2100

func recordsOmitted(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := directoryRecordsOmittedTotal.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// fitRecords gives each record an even share of the frame, then gives the
// room that is left to the larger records, the smallest first. The answer
// fits the frame, a large record does not take the room of a small one,
// and the records keep their order.
func TestFitRecordsSharesTheFrame(t *testing.T) {
	type shape struct{ addrs, addrBytes, allowBytes int }
	small := shape{addrs: 2, addrBytes: 128}
	quarter := shape{addrs: api.DirectoryMaxAddrs / 4, addrBytes: api.DirectoryMaxAddrBytes}
	half := shape{addrs: api.DirectoryMaxAddrs / 2, addrBytes: api.DirectoryMaxAddrBytes}
	threeQuarters := shape{addrs: 3 * api.DirectoryMaxAddrs / 4, addrBytes: api.DirectoryMaxAddrBytes}
	full := shape{addrs: api.DirectoryMaxAddrs, addrBytes: api.DirectoryMaxAddrBytes}
	oversize := shape{addrs: api.DirectoryMaxAddrs, addrBytes: oversizeAddrBytes}
	// The ingress of a record counts as its addresses do.
	oversizeIngress := shape{addrs: 2, addrBytes: 128, allowBytes: directoryMaxMessage}
	for name, tc := range map[string]struct {
		shapes []shape
		want   []int // the positions of the records kept
	}{
		"every record fits":                          {shapes: []shape{small, full, small}, want: []int{0, 1, 2}},
		"a record larger than the frame":             {shapes: []shape{oversize, small, small}, want: []int{1, 2}},
		"an ingress larger than the frame":           {shapes: []shape{small, oversizeIngress, small}, want: []int{0, 2}},
		"full records ahead of small ones":           {shapes: []shape{full, full, small, small}, want: []int{0, 2, 3}},
		"the room left goes to the smallest records": {shapes: []shape{full, half, threeQuarters, quarter, small, small, small, small}, want: []int{1, 2, 3, 4, 5, 6, 7}},
	} {
		t.Run(name, func(t *testing.T) {
			records := make([]*api.PeerRecord, len(tc.shapes))
			var wantOmitted []int
			for i, s := range tc.shapes {
				records[i] = peerRecord(providerWith(t, s.addrs, s.addrBytes))
				if s.allowBytes > 0 {
					records[i].Ingress = &api.ServiceIngress{Allow: []string{"email:" + strings.Repeat("a", s.allowBytes)}}
				}
				if !slices.Contains(tc.want, i) {
					wantOmitted = append(wantOmitted, i)
				}
			}
			positions := func(recs []*api.PeerRecord) []int {
				var out []int
				for _, rec := range recs {
					out = append(out, slices.Index(records, rec))
				}
				return out
			}

			kept, omitted := fitRecords(records, directoryMaxMessage)
			if got := positions(kept); !slices.Equal(got, tc.want) {
				t.Errorf("fitRecords kept the records at %v, want %v", got, tc.want)
			}
			if got := positions(omitted); !slices.Equal(got, wantOmitted) {
				t.Errorf("fitRecords left out the records at %v, want %v", got, wantOmitted)
			}
			data, err := proto.Marshal(&api.DirectoryResponse{Providers: kept})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if len(data) > directoryMaxMessage {
				t.Errorf("the answer is %d bytes, want at most %d", len(data), directoryMaxMessage)
			}
		})
	}
}

// A router answers a lookup in a frame that the reader accepts, whatever
// records it holds. It leaves out and counts a record that does not fit,
// and the other providers are found. In GHSA-gw5v-gc33-3wg6 one record
// under a service type key made every lookup of that type fail.
func TestDirectoryAnswerFitsTheFrame(t *testing.T) {
	a := newDirectoryRouter(t)
	asker := attach(t, a)
	put := func(key []byte, info peer.AddrInfo) {
		a.records.put(key, info.ID, info.Addrs, time.Now())
	}

	t.Run("a record larger than the frame among small ones", func(t *testing.T) {
		key, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			t.Fatal(err)
		}
		large := providerWith(t, api.DirectoryMaxAddrs, oversizeAddrBytes)
		put(key, large)
		for range 5 {
			put(key, providerWith(t, 2, 128))
		}
		var want []string
		for _, info := range held(a, key) {
			if info.ID != large.ID {
				want = append(want, info.ID.String())
			}
		}

		before := recordsOmitted(t)
		resp := ask(t, asker, a.Host.ID(), findProviders(key))
		if resp.GetError() != "" {
			t.Fatalf("find_providers failed: %s", resp.GetError())
		}
		var got []string
		for _, rec := range resp.GetProviders() {
			got = append(got, rec.GetPeerId())
		}
		if !slices.Equal(got, want) {
			t.Errorf("providers = %v, want the small records in the order the router holds them: %v", got, want)
		}
		if got := recordsOmitted(t); got != before+1 {
			t.Errorf("records left out counted = %v, want %v", got, before+1)
		}
	})

	t.Run("as many records of the maximum size as a lookup returns", func(t *testing.T) {
		key, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_INFERENCE, "")
		if err != nil {
			t.Fatal(err)
		}
		for range directoryMaxLimit {
			put(key, providerWith(t, api.DirectoryMaxAddrs, api.DirectoryMaxAddrBytes))
		}
		req := findProviders(key)
		req.GetFindProviders().Limit = directoryMaxLimit

		before := recordsOmitted(t)
		resp := ask(t, asker, a.Host.ID(), req)
		found := len(resp.GetProviders())
		if resp.GetError() != "" || found == 0 {
			t.Fatalf("find_providers found %d providers with error %q, want at least one", found, resp.GetError())
		}
		if got, want := recordsOmitted(t), before+float64(directoryMaxLimit-found); got != want {
			t.Errorf("records left out counted = %v, want %v: %d of %d were found", got, want, found, directoryMaxLimit)
		}
	})

	t.Run("find_peer of a held member whose addresses do not fit", func(t *testing.T) {
		member := attach(t, a)
		a.Host.Peerstore().AddAddrs(member.ID(), providerWith(t, api.DirectoryMaxAddrs, oversizeAddrBytes).Addrs, time.Hour)

		before := recordsOmitted(t)
		resp := ask(t, asker, a.Host.ID(), findPeer(member.ID()))
		if resp.GetError() != "" || resp.GetPeer() != nil {
			t.Fatalf("find_peer answered peer %s with error %q, want no peer: its record is larger than the frame", resp.GetPeer().GetPeerId(), resp.GetError())
		}
		if got := recordsOmitted(t); got != before+1 {
			t.Errorf("records left out counted = %v, want %v", got, before+1)
		}
	})
}

// A lookup merges the addresses that several routers hold for one
// provider. The merge stops at api.DirectoryMaxAddrs, the most a provide
// accepts, and reports how many addresses it left out.
func TestMergeAddrsStopsAtTheRecordBound(t *testing.T) {
	addrs := func(from, to int) []multiaddr.Multiaddr {
		var out []multiaddr.Multiaddr
		for i := from; i < to; i++ {
			a, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/10.0.0.%d/tcp/4001", i))
			if err != nil {
				t.Fatalf("NewMultiaddr: %v", err)
			}
			out = append(out, a)
		}
		return out
	}
	for name, tc := range map[string]struct {
		have, more  []multiaddr.Multiaddr
		want        []multiaddr.Multiaddr
		wantOmitted int
	}{
		"the addresses the record lacks are added": {have: addrs(0, 2), more: addrs(1, 4), want: addrs(0, 4)},
		"a full record takes no more":              {have: addrs(0, api.DirectoryMaxAddrs-2), more: addrs(api.DirectoryMaxAddrs-4, api.DirectoryMaxAddrs+3), want: addrs(0, api.DirectoryMaxAddrs), wantOmitted: 3},
	} {
		t.Run(name, func(t *testing.T) {
			got, omitted := mergeAddrs(tc.have, tc.more)
			if !slices.EqualFunc(got, tc.want, func(a, b multiaddr.Multiaddr) bool { return a.Equal(b) }) {
				t.Errorf("mergeAddrs = %v, want %v", got, tc.want)
			}
			if omitted != tc.wantOmitted {
				t.Errorf("mergeAddrs left out %d addresses, want %d", omitted, tc.wantOmitted)
			}
		})
	}
}

// A member that stops a service withdraws its record: it is gone from the
// router it announced to and from the routers the record was placed on,
// and a lookup from any router no longer names the member. Announcing a
// record again replaces its addresses rather than adding to them, so a
// circuit through a router the member left does not linger.
func TestDirectoryWithdrawAndReplace(t *testing.T) {
	a, b := newDirectoryRouter(t), newDirectoryRouter(t)
	federate(t, a, b)
	member := attach(t, a, "mcp://calculator")
	key, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calculator")
	oldAddr := "/ip4/10.0.0.1/tcp/4001/p2p/" + member.ID().String()
	newAddr := "/ip4/10.0.0.2/tcp/4001/p2p/" + member.ID().String()

	if resp := ask(t, member, a.Host.ID(), provide(key, "mcp://calculator", oldAddr)); resp.GetError() != "" {
		t.Fatalf("provide refused: %s", resp.GetError())
	}
	if resp := ask(t, member, a.Host.ID(), provide(key, "mcp://calculator", newAddr)); resp.GetError() != "" {
		t.Fatalf("second provide refused: %s", resp.GetError())
	}
	for name, router := range map[string]*Router{"own router": a, "placed on": b} {
		provs := held(router, key)
		if len(provs) != 1 || len(provs[0].Addrs) != 1 || provs[0].Addrs[0].String() != "/ip4/10.0.0.2/tcp/4001" {
			t.Fatalf("%s holds %v, want the member at its new address only", name, provs)
		}
	}

	before := directoryCount(t, directoryOpWithdraw, directoryResultOK)
	if resp := ask(t, member, a.Host.ID(), withdraw(key)); resp.GetError() != "" {
		t.Fatalf("withdraw refused: %s", resp.GetError())
	}
	if got := directoryCount(t, directoryOpWithdraw, directoryResultOK); got != before+1 {
		t.Fatalf("withdrawals counted = %v, want %v", got, before+1)
	}
	for name, router := range map[string]*Router{"own router": a, "placed on": b} {
		if provs := held(router, key); len(provs) != 0 {
			t.Fatalf("%s still holds %v after the withdrawal", name, provs)
		}
	}
	asker := attach(t, b)
	if resp := ask(t, asker, b.Host.ID(), findProviders(key)); resp.GetError() != "" || len(resp.GetProviders()) != 0 {
		t.Fatalf("find_providers after the withdrawal = %v, want nobody", resp)
	}
	// Withdrawing again is not an error: the record may have expired.
	if resp := ask(t, member, a.Host.ID(), withdraw(key)); resp.GetError() != "" {
		t.Fatalf("withdrawing a record that is gone: %s", resp.GetError())
	}
	// A member withdraws its own records only.
	stranger := newClient(t, a)
	named := &api.DirectoryRequest{Request: &api.DirectoryRequest_Withdraw{Withdraw: &api.DirectoryWithdraw{Key: key, Provider: stranger.ID().String()}}}
	if resp := ask(t, member, a.Host.ID(), named); resp.GetError() == "" {
		t.Fatal("a member withdrew a record naming another provider")
	}
}

// A record lives for the mesh's record TTL after its last announcement:
// announcing it again extends it, and the sweep drops what expired.
func TestRecordStoreExpiry(t *testing.T) {
	store := newRecordStore(time.Minute)
	p1, p2 := peer.ID("p1"), peer.ID("p2")
	key := []byte("k")
	t0 := time.Unix(1000, 0)
	store.put(key, p1, nil, t0)
	store.put(key, p2, nil, t0.Add(30*time.Second))
	if got := store.providers(key, t0.Add(59*time.Second)); len(got) != 2 {
		t.Fatalf("providers before expiry = %v, want both", got)
	}
	if got := store.providers(key, t0.Add(time.Minute)); len(got) != 1 || got[0].ID != p2 {
		t.Fatalf("providers at the first record's expiry = %v, want the second only", got)
	}
	store.put(key, p1, nil, t0.Add(time.Minute))
	if got := store.sweep(t0.Add(90 * time.Second)); got != 1 {
		t.Fatalf("sweep dropped %d records, want 1: the second, not the first that was announced again", got)
	}
	if got := store.providers(key, t0.Add(90*time.Second)); len(got) != 1 || got[0].ID != p1 {
		t.Fatalf("providers after the sweep = %v, want the first", got)
	}
	if store.sweep(t0.Add(3*time.Minute)) != 1 || store.size() != 0 {
		t.Fatalf("the store holds %d records after everything expired, want 0", store.size())
	}
	if got := recordSweepInterval(15 * time.Minute); got != time.Minute {
		t.Fatalf("sweep interval for a 15m TTL = %s, want 1m", got)
	}
	if got := recordSweepInterval(6 * time.Second); got != 2*time.Second {
		t.Fatalf("sweep interval for a 6s TTL = %s, want 2s", got)
	}
}

// A member serves only what its credential grants: a record for a service
// its role does not allow publishing is refused and counted as denied, and
// nothing is stored; its own record under its peer key needs no grant. The
// grant is checked as a service grant is: by name, by type, or for all.
func TestDirectoryDeniesWhatTheCredentialDoesNotGrant(t *testing.T) {
	a := newDirectoryRouter(t)
	calc, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calculator")
	mcpAll, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "")
	weather, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "weather")
	llm, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_INFERENCE, "llm")
	calcV2, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calc.v2")

	for name, tc := range map[string]struct {
		publish []string
		req     *api.DirectoryRequest
		denied  bool
	}{
		"no grant, a service":            {publish: nil, req: provide(calc, "mcp://calculator"), denied: true},
		"no grant, its own peer key":     {publish: nil, req: nil},
		"exact grant, that service":      {publish: []string{"mcp://calculator"}, req: provide(calc, "mcp://calculator")},
		"exact grant, by type too":       {publish: []string{"mcp://calculator"}, req: provide(mcpAll, "mcp://calculator")},
		"exact grant, another service":   {publish: []string{"mcp://calculator"}, req: provide(weather, "mcp://weather"), denied: true},
		"type grant, any of the type":    {publish: []string{"mcp://*"}, req: provide(weather, "mcp://weather")},
		"type grant, another type":       {publish: []string{"mcp://*"}, req: provide(llm, "inference://llm"), denied: true},
		"prefix grant":                   {publish: []string{"mcp://calc.*"}, req: provide(calc, "mcp://calculator"), denied: true},
		"prefix grant matching":          {publish: []string{"mcp://calc.*"}, req: provide(calcV2, "mcp://calc.v2")},
		"everything":                     {publish: []string{"*"}, req: provide(llm, "inference://llm")},
		"a set of exact grants":          {publish: []string{"mcp://weather", "mcp://calculator"}, req: provide(calc, "mcp://calculator")},
		"a set of exact grants, another": {publish: []string{"mcp://weather", "mcp://clock"}, req: provide(calc, "mcp://calculator"), denied: true},
	} {
		t.Run(name, func(t *testing.T) {
			member := attach(t, a, tc.publish...)
			req := tc.req
			if req == nil {
				req = provide(api.PeerKey(member.ID()), "")
			}
			before := directoryCount(t, directoryOpProvide, directoryResultDenied)
			resp := ask(t, member, a.Host.ID(), req)
			if tc.denied {
				if resp.GetError() == "" {
					t.Fatal("stored; want a refusal")
				}
				if got := directoryCount(t, directoryOpProvide, directoryResultDenied); got != before+1 {
					t.Fatalf("denied counted = %v, want %v", got, before+1)
				}
				if provs := held(a, req.GetProvide().GetKey()); slices.ContainsFunc(provs, func(p peer.AddrInfo) bool { return p.ID == member.ID() }) {
					t.Fatalf("a denied record was stored: %v", provs)
				}
				return
			}
			if resp.GetError() != "" {
				t.Fatalf("refused: %s", resp.GetError())
			}
			if provs := held(a, req.GetProvide().GetKey()); !slices.ContainsFunc(provs, func(p peer.AddrInfo) bool { return p.ID == member.ID() }) {
				t.Fatalf("the record was not stored: %v", provs)
			}
		})
	}

	// A member whose credential the router no longer holds is refused too.
	member := attach(t, a, "mcp://calculator")
	a.credentials.Delete(member.ID())
	if resp := ask(t, member, a.Host.ID(), provide(calc, "mcp://calculator")); resp.GetError() == "" {
		t.Fatal("stored with no credential held; want a refusal")
	}

	// The mesh policy the router synced grants too: a credential carrying
	// role("member") and no publish fact is granted what the policy gives
	// that role now, so a policy change does not wait for the member's next
	// credential.
	member = attach(t, a)
	if resp := ask(t, member, a.Host.ID(), provide(weather, "mcp://weather")); resp.GetError() == "" {
		t.Fatal("stored under a policy granting nothing; want a refusal")
	}
	rules, _ := api.BuildPolicyRules([]*api.PolicyRole{{Name: "member", AllowedPublish: []string{"mcp://weather"}}}, nil)
	texts := api.PolicyRuleTexts(rules)
	parsed, err := api.ParseDatalogRules(texts)
	if err != nil {
		t.Fatal(err)
	}
	a.policy.Store(&meshPolicy{rules: parsed, texts: texts})
	if resp := ask(t, member, a.Host.ID(), provide(weather, "mcp://weather")); resp.GetError() != "" {
		t.Fatalf("refused under a policy granting the role mcp://weather: %s", resp.GetError())
	}
	if resp := ask(t, member, a.Host.ID(), provide(calc, "mcp://calculator")); resp.GetError() == "" {
		t.Fatal("stored mcp://calculator under a policy granting the role mcp://weather only; want a refusal")
	}
}
