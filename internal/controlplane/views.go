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

package controlplane

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
)

// The operator plane (/admin/*, /user/*) serves api.proto messages; these
// render the store's records into them, leaving credentials and key material
// behind.

// timestampOrNil keeps a zero time unset, which protojson omits.
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func bootstrapTokenView(t *storage.BootstrapToken) *api.BootstrapToken {
	v := &api.BootstrapToken{
		Id:                 t.ID,
		Role:               t.Role,
		OwnerId:            t.OwnerID,
		MaxUsages:          int32(t.MaxUsages),
		UsagesCount:        int32(t.UsagesCount),
		Description:        t.Description,
		CreateTime:         timestampOrNil(t.CreatedAt),
		ExpireTime:         timestampOrNil(t.ExpiresAt),
		AutonomousRecovery: t.AutonomousRecovery,
		Ephemeral:          t.Ephemeral,
	}
	if t.RevokedAt != nil {
		v.RevokeTime = timestamppb.New(*t.RevokedAt)
	}
	return v
}

func bootstrapTokenViews(list []storage.BootstrapToken) []*api.BootstrapToken {
	out := make([]*api.BootstrapToken, 0, len(list))
	for i := range list {
		out = append(out, bootstrapTokenView(&list[i]))
	}
	return out
}

func enrollmentRequestView(r *storage.EnrollmentRequest) *api.EnrollmentRequest {
	v := &api.EnrollmentRequest{
		Id:         r.ID,
		PeerId:     r.PeerID,
		TokenId:    r.TokenID,
		Status:     r.Status,
		Labels:     r.Labels,
		CreateTime: timestampOrNil(r.CreatedAt),
		ResolvedBy: r.ResolvedBy,
	}
	if r.ResolvedAt != nil {
		v.ResolveTime = timestamppb.New(*r.ResolvedAt)
	}
	return v
}

func enrollmentRequestViews(list []storage.EnrollmentRequest) []*api.EnrollmentRequest {
	out := make([]*api.EnrollmentRequest, 0, len(list))
	for i := range list {
		out = append(out, enrollmentRequestView(&list[i]))
	}
	return out
}

func userView(u *storage.User) *api.User {
	return &api.User{
		Id:         u.ID,
		Issuer:     u.Issuer,
		Email:      u.Email,
		Role:       u.Role,
		CreateTime: timestampOrNil(u.CreatedAt),
	}
}

func userViews(list []storage.User) []*api.User {
	out := make([]*api.User, 0, len(list))
	for i := range list {
		out = append(out, userView(&list[i]))
	}
	return out
}

// enrolledNodeView drops the node's biscuit and public key. The identity
// provider's claims are admin material.
func enrolledNodeView(n *storage.EnrolledNode, withClaims bool) *api.EnrolledNode {
	v := &api.EnrolledNode{
		PeerId:             n.PeerID,
		Role:               n.Role,
		EnrollmentType:     n.EnrollmentType,
		OwnerId:            n.OwnerID,
		Labels:             n.Labels,
		EnrollTime:         timestampOrNil(n.EnrolledAt),
		ExpireTime:         timestampOrNil(n.ExpiresAt),
		Banned:             n.Banned,
		AutonomousRecovery: n.AutonomousRecovery,
		Ephemeral:          n.Ephemeral,
	}
	if withClaims {
		v.ClaimsJson = n.ClaimsJSON
	}
	return v
}

func routerLeaseView(l *storage.RouterLease) *api.RouterLease {
	return &api.RouterLease{
		PeerId:          l.PeerID,
		Addresses:       l.Addresses,
		LastRenewalTime: timestampOrNil(l.LastRenewal),
		ExpireTime:      timestampOrNil(l.ExpiresAt),
		ConnectedPeers:  l.ConnectedPeers,
		DhtSize:         int32(l.DHTSize),
		IngressUrl:      l.IngressURL,
	}
}

func routerLeaseViews(list []storage.RouterLease) []*api.RouterLease {
	out := make([]*api.RouterLease, 0, len(list))
	for i := range list {
		out = append(out, routerLeaseView(&list[i]))
	}
	return out
}
