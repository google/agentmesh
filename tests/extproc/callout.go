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

// Package extproc implements a reference Envoy ExternalProcessor callout server
// using official grpc-go and envoyproxy/go-control-plane bindings to verify
// wire-level interoperability with SAM's zero-dependency stdlib gRPC implementation.
package extproc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CalloutServer is a reference Google Service Extensions / Envoy ext_proc callout
// server built on grpc-go and go-control-plane.
type CalloutServer struct {
	extprocv3.UnimplementedExternalProcessorServer

	mu            sync.Mutex
	lastSamAttrs  map[string]*structpb.Value
	hadDeadline   bool
	sleepDuration time.Duration
}

func NewCalloutServer() *CalloutServer {
	return &CalloutServer{}
}

func (s *CalloutServer) SetSleepDuration(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleepDuration = d
}

func (s *CalloutServer) LastSamAttributes() map[string]*structpb.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*structpb.Value, len(s.lastSamAttrs))
	for k, v := range s.lastSamAttrs {
		out[k] = v
	}
	return out
}

func (s *CalloutServer) LastStreamHadDeadline() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hadDeadline
}

func (s *CalloutServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	_, hasDeadline := stream.Context().Deadline()
	s.mu.Lock()
	s.hadDeadline = hasDeadline
	s.mu.Unlock()

	s.mu.Lock()
	sleep := s.sleepDuration
	s.mu.Unlock()
	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		if samAttrs := req.GetAttributes()["sam"]; samAttrs != nil {
			s.mu.Lock()
			s.lastSamAttrs = samAttrs.GetFields()
			s.mu.Unlock()
		}

		var resp *extprocv3.ProcessingResponse
		switch phase := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			var path string
			for _, hv := range phase.RequestHeaders.GetHeaders().GetHeaders() {
				if hv.GetKey() == ":path" {
					path = hv.GetValue()
					if path == "" {
						path = string(hv.GetRawValue())
					}
				}
			}
			if path == "/trailers-only-error" {
				return status.Error(codes.PermissionDenied, "trailers-only rejection from grpc-go")
			}
			if path == "/immediate-deny" {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_ImmediateResponse{
						ImmediateResponse: &extprocv3.ImmediateResponse{
							Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
							Body:    []byte("denied by service extensions callout"),
							Details: "service_extension_block",
						},
					},
				}
			} else {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestHeaders{
						RequestHeaders: &extprocv3.HeadersResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
								HeaderMutation: &extprocv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header:       &corev3.HeaderValue{Key: "X-Callout-Inspected", Value: "true"},
											Append:       wrapperspb.Bool(false),
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
										{
											// Attempted mutation of protected header; sam-node must ignore it.
											Header:       &corev3.HeaderValue{Key: "Authorization", Value: "Bearer forged"},
											Append:       wrapperspb.Bool(false),
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
								},
							},
						},
					},
					ModeOverride: &extprocv3http.ProcessingMode{
						RequestBodyMode:  extprocv3http.ProcessingMode_BUFFERED,
						ResponseBodyMode: extprocv3http.ProcessingMode_BUFFERED,
					},
				}
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			body := phase.RequestBody.GetBody()
			if strings.Contains(string(body), "BLOCK_BODY") {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_ImmediateResponse{
						ImmediateResponse: &extprocv3.ImmediateResponse{
							Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
							Body:    []byte("request body blocked"),
							Details: "body_policy_violation",
						},
					},
				}
			} else {
				mutated := bytes.ReplaceAll(body, []byte("PII_SSN"), []byte("[REDACTED_SSN]"))
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE_AND_REPLACE,
								BodyMutation: &extprocv3.BodyMutation{
									Mutation: &extprocv3.BodyMutation_Body{Body: mutated},
								},
							},
						},
					},
				}
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
							HeaderMutation: &extprocv3.HeaderMutation{
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header:       &corev3.HeaderValue{Key: "X-Callout-Response", Value: "verified"},
										Append:       wrapperspb.Bool(false),
										AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
									},
								},
							},
						},
					},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			mutated := bytes.ReplaceAll(phase.ResponseBody.GetBody(), []byte("RAW_OUTPUT"), []byte("SANITIZED_OUTPUT"))
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE_AND_REPLACE,
							BodyMutation: &extprocv3.BodyMutation{
								Mutation: &extprocv3.BodyMutation_Body{Body: mutated},
							},
						},
					},
				},
			}
		}

		if resp != nil {
			if err := stream.Send(resp); err != nil {
				return err
			}
			if resp.GetImmediateResponse() != nil {
				return nil
			}
		}
	}
}
