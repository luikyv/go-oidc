package goidc_test

import (
	"encoding/json"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSSFSubjectMarshalJSON_InlinesAdditionalMembers(t *testing.T) {
	// Given.
	subject := goidc.SSFSubject{
		Format: goidc.SSFSubjectFormatComplex,
		User: &goidc.SSFSubject{
			Format: goidc.SSFSubjectFormatEmail,
			Email:  "user@example.com",
		},
		AdditionalMembers: map[string]goidc.SSFSubject{
			"custom": {
				Format: goidc.SSFSubjectFormatOpaque,
				ID:     "custom_subject",
			},
		},
	}

	// When.
	data, err := json.Marshal(subject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error unmarshalling: %v", err)
	}

	if _, ok := raw["additional_members"]; ok {
		t.Fatal("additional_members should not be serialized")
	}
	custom, ok := raw["custom"].(map[string]any)
	if !ok {
		t.Fatalf("custom = %T, want object", raw["custom"])
	}
	if custom["format"] != string(goidc.SSFSubjectFormatOpaque) {
		t.Fatalf("custom.format = %v, want opaque", custom["format"])
	}
	if custom["id"] != "custom_subject" {
		t.Fatalf("custom.id = %v, want custom_subject", custom["id"])
	}
}

func TestSSFSubjectUnmarshalJSON_CollectsAdditionalMembers(t *testing.T) {
	// Given.
	data := []byte(`{
		"format": "complex",
		"user": {
			"format": "email",
			"email": "user@example.com"
		},
		"custom": {
			"format": "opaque",
			"id": "custom_subject"
		}
	}`)

	// When.
	var subject goidc.SSFSubject
	if err := json.Unmarshal(data, &subject); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	if subject.User == nil {
		t.Fatal("User should not be nil")
	}
	custom, ok := subject.AdditionalMembers["custom"]
	if !ok {
		t.Fatal("custom additional member not found")
	}
	if custom.Format != goidc.SSFSubjectFormatOpaque {
		t.Fatalf("custom.Format = %q, want opaque", custom.Format)
	}
	if custom.ID != "custom_subject" {
		t.Fatalf("custom.ID = %q, want custom_subject", custom.ID)
	}
}
