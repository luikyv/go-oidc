package federation

import (
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMetadata_Merge_SubordinateHasNoClientMetadata(t *testing.T) {
	// Given: subordinate statement has no client metadata, entity config has full metadata.
	subordinate := metadata{
		OpenIDClient: nil,
	}
	entityConfig := metadata{
		OpenIDClient: &goidc.ClientMeta{
			GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			RedirectURIs:  []string{"https://client.example.com/callback"},
		},
	}

	// When.
	result, err := subordinate.Merge(entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OpenIDClient == nil {
		t.Fatal("OpenIDClient should not be nil")
	}

	if len(result.OpenIDClient.GrantTypes) != 2 {
		t.Errorf("GrantTypes = %v, want 2 elements", result.OpenIDClient.GrantTypes)
	}

	if len(result.OpenIDClient.ResponseTypes) != 1 {
		t.Errorf("ResponseTypes = %v, want 1 element", result.OpenIDClient.ResponseTypes)
	}

	if len(result.OpenIDClient.RedirectURIs) != 1 {
		t.Errorf("RedirectURIs = %v, want 1 element", result.OpenIDClient.RedirectURIs)
	}
}

func TestMetadata_Merge_SubordinateOverridesEntityConfig(t *testing.T) {
	// Given: subordinate statement overrides some fields from entity config.
	subordinate := metadata{
		OpenIDClient: &goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
		},
	}
	entityConfig := metadata{
		OpenIDClient: &goidc.ClientMeta{
			GrantTypes:       []goidc.GrantType{goidc.GrantAuthorizationCode},
			TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
			RedirectURIs:     []string{"https://client.example.com/callback"},
		},
	}

	// When.
	result, err := subordinate.Merge(entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Subordinate's value should override.
	if result.OpenIDClient.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT {
		t.Errorf("TokenAuthnMethod = %v, want %v", result.OpenIDClient.TokenAuthnMethod, goidc.AuthnMethodPrivateKeyJWT)
	}

	// Entity config's values should be preserved.
	if len(result.OpenIDClient.GrantTypes) != 1 {
		t.Errorf("GrantTypes = %v, want 1 element", result.OpenIDClient.GrantTypes)
	}

	if len(result.OpenIDClient.RedirectURIs) != 1 {
		t.Errorf("RedirectURIs = %v, want 1 element", result.OpenIDClient.RedirectURIs)
	}
}

func TestMetadata_Merge_BothHaveNoClientMetadata(t *testing.T) {
	// Given: neither has client metadata.
	subordinate := metadata{
		OpenIDClient: nil,
	}
	entityConfig := metadata{
		OpenIDClient: nil,
	}

	// When.
	result, err := subordinate.Merge(entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OpenIDClient != nil {
		t.Error("OpenIDClient should be nil")
	}
}

func TestMetadata_Merge_OnlySubordinateHasClientMetadata(t *testing.T) {
	// Given: only subordinate has client metadata.
	subordinate := metadata{
		OpenIDClient: &goidc.ClientMeta{
			GrantTypes: []goidc.GrantType{goidc.GrantClientCredentials},
		},
	}
	entityConfig := metadata{
		OpenIDClient: nil,
	}

	// When.
	result, err := subordinate.Merge(entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When entity config has no client metadata, subordinate's metadata is not used
	// (per the spec, we're merging subordinate INTO entity config).
	if result.OpenIDClient != nil {
		t.Error("OpenIDClient should be nil when entity config has no client metadata")
	}
}

func TestMetadata_Merge_PreservesAllEntityConfigFields(t *testing.T) {
	// Given: entity config has many fields, subordinate has none.
	subordinate := metadata{
		OpenIDClient: nil,
	}
	entityConfig := metadata{
		OpenIDClient: &goidc.ClientMeta{
			Name:              "Test Client",
			GrantTypes:        []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken},
			ResponseTypes:     []goidc.ResponseType{goidc.ResponseTypeCode},
			RedirectURIs:      []string{"https://client.example.com/callback"},
			TokenAuthnMethod:  goidc.AuthnMethodSecretBasic,
			ScopeIDs:          "openid profile",
			IDTokenSigAlg:     goidc.RS256,
			ApplicationType:   goidc.ApplicationTypeWeb,
			Contacts:          []string{"admin@example.com"},
			PolicyURI:         "https://client.example.com/policy",
			TermsOfServiceURI: "https://client.example.com/tos",
			JARIsRequired:     true,
			PARIsRequired:     true,
			SubIdentifierType: goidc.SubIdentifierPublic,
			DefaultMaxAgeSecs: ptr(3600),
		},
	}

	// When.
	result, err := subordinate.Merge(entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c := result.OpenIDClient
	if c.Name != "Test Client" {
		t.Errorf("Name = %v, want 'Test Client'", c.Name)
	}
	if len(c.GrantTypes) != 2 {
		t.Errorf("GrantTypes = %v, want 2 elements", c.GrantTypes)
	}
	if len(c.ResponseTypes) != 1 {
		t.Errorf("ResponseTypes = %v, want 1 element", c.ResponseTypes)
	}
	if len(c.RedirectURIs) != 1 {
		t.Errorf("RedirectURIs = %v, want 1 element", c.RedirectURIs)
	}
	if c.TokenAuthnMethod != goidc.AuthnMethodSecretBasic {
		t.Errorf("TokenAuthnMethod = %v, want %v", c.TokenAuthnMethod, goidc.AuthnMethodSecretBasic)
	}
	if c.ScopeIDs != "openid profile" {
		t.Errorf("ScopeIDs = %v, want 'openid profile'", c.ScopeIDs)
	}
	if c.IDTokenSigAlg != goidc.RS256 {
		t.Errorf("IDTokenSigAlg = %v, want %v", c.IDTokenSigAlg, goidc.RS256)
	}
	if c.ApplicationType != goidc.ApplicationTypeWeb {
		t.Errorf("ApplicationType = %v, want %v", c.ApplicationType, goidc.ApplicationTypeWeb)
	}
	if len(c.Contacts) != 1 {
		t.Errorf("Contacts = %v, want 1 element", c.Contacts)
	}
	if c.PolicyURI != "https://client.example.com/policy" {
		t.Errorf("PolicyURI = %v, want 'https://client.example.com/policy'", c.PolicyURI)
	}
	if c.TermsOfServiceURI != "https://client.example.com/tos" {
		t.Errorf("TermsOfServiceURI = %v, want 'https://client.example.com/tos'", c.TermsOfServiceURI)
	}
	if !c.JARIsRequired {
		t.Error("JARIsRequired should be true")
	}
	if !c.PARIsRequired {
		t.Error("PARIsRequired should be true")
	}
	if c.SubIdentifierType != goidc.SubIdentifierPublic {
		t.Errorf("SubIdentifierType = %v, want %v", c.SubIdentifierType, goidc.SubIdentifierPublic)
	}
	if c.DefaultMaxAgeSecs == nil || *c.DefaultMaxAgeSecs != 3600 {
		t.Errorf("DefaultMaxAgeSecs = %v, want 3600", c.DefaultMaxAgeSecs)
	}
}

func ptr[T any](v T) *T {
	return &v
}
