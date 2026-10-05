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

package bench

import (
	"context"
	"testing"
)

func TestRunSTS(t *testing.T) {
	ctx := context.Background()
	rep, err := RunSTS(ctx, STSOptions{
		Requests:          20,
		Concurrency:       2,
		Warmup:            2,
		Workloads:         2,
		RequestsPerMinute: 10,
	})
	if err != nil {
		t.Fatalf("RunSTS failed: %v", err)
	}
	if rep.TokenExchangeUncached.Succeeded != 20 || rep.TokenExchangeUncached.ControlPlaneCalls != 20 {
		t.Fatalf("unexpected TokenExchangeUncached report: %+v", rep.TokenExchangeUncached)
	}
	if rep.STSTokenUncached.Succeeded != 20 || rep.STSTokenUncached.ControlPlaneCalls != 20 {
		t.Fatalf("unexpected STSTokenUncached report: %+v", rep.STSTokenUncached)
	}
	if rep.TokenExchangeSVID5m.Succeeded != 20 || rep.TokenExchangeSVID5m.CacheHitRate <= 0.8 {
		t.Fatalf("expected high cache hit rate for 5m SVIDs, got %+v", rep.TokenExchangeSVID5m)
	}
	if rep.TokenExchangeK8s1h.Succeeded != 20 || rep.TokenExchangeK8s1h.CacheHitRate <= 0.8 {
		t.Fatalf("expected high cache hit rate for 1h K8s projected tokens, got %+v", rep.TokenExchangeK8s1h)
	}
	if rep.STSTokenCached.Succeeded != 20 || rep.STSTokenCached.CacheHitRate <= 0.8 {
		t.Fatalf("expected high cache hit rate for cached STS border JWTs, got %+v", rep.STSTokenCached)
	}
}
