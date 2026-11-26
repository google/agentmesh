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

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Labels are free-form, control-plane-attested key=value metadata a node's
// identity carries (e.g. region="us-east-1", team="platform"). Cloud
// providers, on-prem operators, and countries all name things differently,
// so Agent Mesh imposes no taxonomy or hierarchy on keys or values: composition
// (e.g. attesting both a precise and a coarser value so a coarser
// requirement also matches) is entirely up to the operator. Matching is
// exact and case-sensitive on both key and value (see LabelCheck).
//
// Keys are plain conventions agreed by operators (e.g. "region"); Agent Mesh does
// not reserve or interpret any key beyond ValidateLabelKey/ValidateLabelValue.

// labelKeySyntax bounds label keys to a safe, portable charset.
var labelKeySyntax = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,63}$`)

// maxLabelValueLen bounds label values defensively; well within any
// realistic cloud region/zone or on-prem naming convention.
const maxLabelValueLen = 255

// MaxNodeLabels bounds the number of labels a single node may declare at
// enrollment so label facts cannot exhaust the Biscuit authorizer fact budget.
const MaxNodeLabels = 64

// ValidateLabelKey checks that a label key is well-formed: 1-63 characters
// from [a-zA-Z0-9_.-].
func ValidateLabelKey(key string) error {
	if !labelKeySyntax.MatchString(key) {
		return fmt.Errorf("invalid label key %q: must be 1-63 chars of [a-zA-Z0-9_.-]", key)
	}
	return nil
}

// ValidateLabelValue checks that a label value is well-formed: non-empty,
// bounded length, and free of characters that collide with the wire-format
// separators (comma-separated key=value pairs) or control characters.
func ValidateLabelValue(value string) error {
	if value == "" {
		return fmt.Errorf("label value must not be empty")
	}
	if len(value) > maxLabelValueLen {
		return fmt.Errorf("label value %q exceeds %d characters", value, maxLabelValueLen)
	}
	if strings.ContainsAny(value, ",=\n\r\t") {
		return fmt.Errorf("label value %q must not contain ',', '=', or control characters", value)
	}
	if err := validateBindingMemberCharset(value); err != nil {
		return fmt.Errorf("label value %q %w", value, err)
	}
	return nil
}

// ValidateLabels checks every key and value in a label set. Keys are visited
// in lexicographic order, so the error returned for a given input is
// deterministic and stable across runs (Go's map iteration is randomized).
func ValidateLabels(labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}
	if len(labels) > MaxNodeLabels {
		return fmt.Errorf("too many labels (%d): maximum is %d", len(labels), MaxNodeLabels)
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := ValidateLabelKey(k); err != nil {
			return err
		}
		if err := ValidateLabelValue(labels[k]); err != nil {
			return err
		}
	}
	return nil
}

// FormatLabels renders a label map as canonical comma-separated "key=value"
// pairs sorted by key. Returns "" when labels is empty.
func FormatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

// ParseLabelFlags turns repeated "key=value" flag values into a label set
// that passes ValidateLabels. nil for none.
func ParseLabelFlags(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(raw))
	for _, l := range raw {
		key, value, found := strings.Cut(l, "=")
		if !found {
			return nil, fmt.Errorf("label %q is not key=value", l)
		}
		labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := ValidateLabels(labels); err != nil {
		return nil, err
	}
	return labels, nil
}

// A node declares its own labels when it enrols, so on its own a label is a
// claim rather than an attestation. A role's allowed_labels is what makes it
// one: the control plane only signs a label the operator said that role may
// carry. Without it a node could declare region="us-east-1" and satisfy every
// peer that requires it.

// ValidateLabelPattern checks one entry of a role's allowed_labels. The forms
// are "*" for any label at all, "key=*" for any value of a key, and "key=value"
// for one exact pair.
func ValidateLabelPattern(pattern string) error {
	if pattern == "*" {
		return nil
	}
	key, value, found := strings.Cut(pattern, "=")
	if !found {
		return fmt.Errorf("invalid allowed_label %q: must be \"*\", \"key=*\" or \"key=value\"", pattern)
	}
	if err := ValidateLabelKey(key); err != nil {
		return fmt.Errorf("invalid allowed_label %q: %w", pattern, err)
	}
	if value == "*" {
		return nil
	}
	if err := ValidateLabelValue(value); err != nil {
		return fmt.Errorf("invalid allowed_label %q: %w", pattern, err)
	}
	return nil
}

// LabelPatternsAllow reports whether patterns permit every declared label,
// naming the first one they do not. Keys are visited in order so the error for
// a given input is stable.
func LabelPatternsAllow(patterns []string, labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !labelAllowed(patterns, key, labels[key]) {
			return fmt.Errorf("label %q=%q is not permitted by this identity's roles", key, labels[key])
		}
	}
	return nil
}

func labelAllowed(patterns []string, key, value string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		pKey, pValue, found := strings.Cut(p, "=")
		if !found || pKey != key {
			continue
		}
		if pValue == "*" || pValue == value {
			return true
		}
	}
	return false
}
