package federation

import (
	"encoding/json"
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMetadataPolicy_Validate(t *testing.T) {
	// Given.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}

	// When.
	err := policy.Validate()

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Merge(t *testing.T) {
	// Given.
	highPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	lowPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}

	// When.
	_, err := highPolicy.Merge(lowPolicy)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Apply(t *testing.T) {
	// Given.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	statement := entityStatement{
		Metadata: metadata{
			OpenIDClient: &client.Client{},
		},
	}

	// When.
	_, err := policy.Apply(oidctest.NewContext(t), statement)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Apply_EssentialMissing(t *testing.T) {
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{
			TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
				Essential: true,
			},
		},
	}
	statement := entityStatement{
		Metadata: metadata{
			OpenIDClient: &client.Client{},
		},
	}
	_, err := policy.Apply(oidctest.NewContext(t), statement)
	if err == nil {
		t.Fatal("error expected: essential field TokenAuthnMethod is not set")
	}
}

func TestMetadataPolicy_Validate_NilOpenIDClient(t *testing.T) {
	// Given: policy without OpenIDClient.
	policy := metadataPolicy{
		OpenIDClient: nil,
	}

	// When.
	err := policy.Validate()

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMetadataPolicy_Merge_LowPolicyNilOpenIDClient(t *testing.T) {
	// Given.
	highPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{
			Name: metadataOperators[string]{Value: nullable[string]{Set: true, Value: "TestClient"}},
		},
	}
	lowPolicy := metadataPolicy{
		OpenIDClient: nil,
	}

	// When.
	merged, err := highPolicy.Merge(lowPolicy)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if merged.OpenIDClient == nil {
		t.Error("merged.OpenIDClient should not be nil")
	}
}

func TestMetadataPolicy_Merge_HighPolicyNilOpenIDClient(t *testing.T) {
	// Given.
	highPolicy := metadataPolicy{
		OpenIDClient: nil,
	}
	lowPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{
			Name: metadataOperators[string]{Value: nullable[string]{Set: true, Value: "LowClient"}},
		},
	}

	// When.
	merged, err := highPolicy.Merge(lowPolicy)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if merged.OpenIDClient == nil {
		t.Error("merged.OpenIDClient should not be nil")
	}
}

func TestMetadataPolicy_Apply_NilOpenIDClientMetadata(t *testing.T) {
	// Given: statement without OpenIDClient metadata.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	statement := entityStatement{
		Metadata: metadata{
			OpenIDClient: nil,
		},
	}

	// When.
	result, err := policy.Apply(oidctest.NewContext(t), statement)

	// Then: no error because there's nothing to apply to.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Metadata.OpenIDClient != nil {
		t.Error("expected OpenIDClient to remain nil")
	}
}

func TestOpenIDClientMetadataPolicy_Validate_WithCustomAttributes(t *testing.T) {
	// Given: policy with custom attributes.
	policy := openIDClientMetadataPolicy{}
	policy.setCustomAttribute("custom_field", metadataOperators[any]{
		Value: nullable[any]{Set: true, Value: "custom_value"},
	})

	// When.
	err := policy.Validate()

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenIDClientMetadataPolicy_Merge_WithCustomAttributes(t *testing.T) {
	// Given.
	high := openIDClientMetadataPolicy{}
	high.setCustomAttribute("high_attr", metadataOperators[any]{
		Value: nullable[any]{Set: true, Value: "high_value"},
	})

	low := openIDClientMetadataPolicy{}
	low.setCustomAttribute("low_attr", metadataOperators[any]{
		Value: nullable[any]{Set: true, Value: "low_value"},
	})

	// When.
	merged, err := high.Merge(low)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !merged.customAttribute("low_attr").Value.Set {
		t.Error("expected low_attr to be present in merged policy")
	}
}

func TestOpenIDClientMetadataPolicy_Apply_WithScopeIDs(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{
		ScopeIDs: metadataOperators[[]string]{
			SupersetOf: []string{"openid"},
		},
	}
	c := client.Client{ClientMeta: goidc.ClientMeta{
		ScopeIDs: "openid profile",
	}}

	// When.
	result, err := policy.Apply(c)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScopeIDs != "openid profile" {
		t.Errorf("result.ScopeIDs = %s, want 'openid profile'", result.ScopeIDs)
	}
}

func TestOpenIDClientMetadataPolicy_Apply_WithCustomAttributes(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{}
	policy.setCustomAttribute("custom_field", metadataOperators[any]{
		Value: nullable[any]{Set: true, Value: "custom_value"},
	})
	c := client.Client{}

	// When.
	result, err := policy.Apply(c)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CustomAttributes["custom_field"] != "custom_value" {
		t.Errorf("custom_field = %v, want 'custom_value'", result.CustomAttributes["custom_field"])
	}
}

func TestOpenIDClientMetadataPolicy_Apply_WithValue(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			Value: nullable[goidc.AuthnMethod]{Set: true, Value: goidc.AuthnMethodPrivateKeyJWT},
		},
	}
	c := client.Client{ClientMeta: goidc.ClientMeta{
		TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
	}}

	// When.
	result, err := policy.Apply(c)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT {
		t.Errorf("result.TokenAuthnMethod = %v, want %v", result.TokenAuthnMethod, goidc.AuthnMethodPrivateKeyJWT)
	}
}

func TestOpenIDClientMetadataPolicy_Apply_WithDefault(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			Default: goidc.AuthnMethodPrivateKeyJWT,
		},
	}
	c := client.Client{
		// TokenAuthnMethod is zero value.
	}

	// When.
	result, err := policy.Apply(c)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT {
		t.Errorf("result.TokenAuthnMethod = %v, want %v", result.TokenAuthnMethod, goidc.AuthnMethodPrivateKeyJWT)
	}
}

func TestOpenIDClientMetadataPolicy_Apply_OneOf_Failure(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			OneOf: []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretBasic},
		},
	}
	c := client.Client{ClientMeta: goidc.ClientMeta{
		TokenAuthnMethod: goidc.AuthnMethodSecretPost,
	}}

	// When.
	_, err := policy.Apply(c)

	// Then.
	if err == nil {
		t.Fatal("error expected when value is not in one_of set")
	}
}

func TestOpenIDClientMetadataPolicy_Apply_Add(t *testing.T) {
	// Given.
	policy := openIDClientMetadataPolicy{
		GrantTypes: metadataOperators[[]goidc.GrantType]{
			Add: []goidc.GrantType{goidc.GrantRefreshToken},
		},
	}
	c := client.Client{ClientMeta: goidc.ClientMeta{
		GrantTypes: []goidc.GrantType{goidc.GrantAuthorizationCode},
	}}

	// When.
	result, err := policy.Apply(c)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.GrantTypes) != 2 {
		t.Errorf("expected 2 grant types, got %d", len(result.GrantTypes))
	}
}

func TestOpenIDClientMetadataPolicy_Validate_InvalidOperator(t *testing.T) {
	// Given: conflicting operators.
	policy := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			Value: nullable[goidc.AuthnMethod]{Set: true, Value: goidc.AuthnMethodPrivateKeyJWT},
			OneOf: []goidc.AuthnMethod{goidc.AuthnMethodSecretBasic},
		},
	}

	// When.
	err := policy.Validate()

	// Then.
	if err == nil {
		t.Fatal("error expected for conflicting operators")
	}
}

func TestOpenIDClientMetadataPolicy_Merge_Operators(t *testing.T) {
	// Given.
	high := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			OneOf: []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretBasic},
		},
	}
	low := openIDClientMetadataPolicy{
		TokenAuthnMethod: metadataOperators[goidc.AuthnMethod]{
			OneOf: []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
		},
	}

	// When.
	merged, err := high.Merge(low)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After merging, the intersection should be just private_key_jwt.
	if len(merged.TokenAuthnMethod.OneOf) != 1 {
		t.Errorf("expected 1 item in merged OneOf, got %d", len(merged.TokenAuthnMethod.OneOf))
	}
}

func TestOpenIDClientMetadataPolicy_UnmarshalJSON_CustomAttributes(t *testing.T) {
	data := []byte(`{
		"client_name": {"one_of": ["example"]},
		"post_logout_redirect_uris": {"add": ["https://client.example.com/logout/callback"]},
		"custom_field": {}
	}`)

	var policy openIDClientMetadataPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.Name.OneOf) != 1 || policy.Name.OneOf[0] != "example" {
		t.Fatalf("unexpected client_name one_of: %+v", policy.Name.OneOf)
	}

	if len(policy.PostLogoutRedirectURIs.Add) != 1 {
		t.Fatalf("unexpected post_logout_redirect_uris add: %+v", policy.PostLogoutRedirectURIs.Add)
	}

	if _, ok := policy.CustomAttributes["custom_field"]; !ok {
		t.Fatal("expected custom_field to be captured as custom attribute")
	}

	if _, ok := policy.CustomAttributes["client_name"]; ok {
		t.Fatal("client_name should not be captured as custom attribute")
	}
}
