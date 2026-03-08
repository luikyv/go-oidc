package dcr

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestResponseMarshalJSON(t *testing.T) {
	// Given.
	resp := response{
		ID:              "client_123",
		Secret:          "secret_value",
		RegistrationURI: "https://example.com/register/client_123",
		ClientMeta: &goidc.ClientMeta{
			Name: "Test Client",
			CustomAttributes: map[string]any{
				"custom_field": "custom_value",
			},
		},
	}

	// When.
	data, err := json.Marshal(resp)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unexpected error unmarshaling result: %v", err)
	}

	if result["client_id"] != "client_123" {
		t.Errorf("client_id = %v, want client_123", result["client_id"])
	}
	if result["client_secret"] != "secret_value" {
		t.Errorf("client_secret = %v, want secret_value", result["client_secret"])
	}
	if result["client_name"] != "Test Client" {
		t.Errorf("client_name = %v, want Test Client", result["client_name"])
	}
	// Custom attributes should be inlined.
	if result["custom_field"] != "custom_value" {
		t.Errorf("custom_field = %v, want custom_value", result["custom_field"])
	}
	// The custom_attributes wrapper key should not appear.
	if _, ok := result["custom_attributes"]; ok {
		t.Error("custom_attributes key should not be present in the output")
	}
}

func TestResponseMarshalJSON_NoCustomAttributes(t *testing.T) {
	// Given.
	resp := response{
		ID:              "client_456",
		RegistrationURI: "https://example.com/register/client_456",
		ClientMeta:      &goidc.ClientMeta{Name: "Simple Client"},
	}

	// When.
	data, err := json.Marshal(resp)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["client_id"] != "client_456" {
		t.Errorf("client_id = %v, want client_456", result["client_id"])
	}
	if _, ok := result["custom_attributes"]; ok {
		t.Error("custom_attributes key should not be present")
	}
}

func TestResponseMarshalJSON_OmitsEmptySecret(t *testing.T) {
	// Given.
	resp := response{
		ID:              "client_789",
		RegistrationURI: "https://example.com/register/client_789",
		ClientMeta:      &goidc.ClientMeta{},
	}

	// When.
	data, err := json.Marshal(resp)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := result["client_secret"]; ok {
		t.Error("client_secret should be omitted when empty")
	}
	if _, ok := result["registration_access_token"]; ok {
		t.Error("registration_access_token should be omitted when empty")
	}
}

func TestRequestUnmarshalJSON(t *testing.T) {
	// Given.
	testCases := []struct {
		payload []byte
		want    request
	}{
		{
			[]byte(`{
				"client_name": "Test Client",
				"logo_uri": "https://example.com/logo.png",
				"custom_field_1": "Value 1",
				"custom_field_2": 123
			}`),
			request{
				&goidc.ClientMeta{
					Name:    "Test Client",
					LogoURI: "https://example.com/logo.png",
					CustomAttributes: map[string]any{
						"custom_field_1": "Value 1",
						"custom_field_2": 123.0,
					},
				},
			},
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// Given.
				var req request

				// When.
				err := json.Unmarshal(testCase.payload, &req)

				// Then.
				if err != nil {
					t.Fatal(err)
				}

				if diff := cmp.Diff(req, testCase.want); diff != "" {
					t.Error(diff)
				}
			},
		)
	}
}
