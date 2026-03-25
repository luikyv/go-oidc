package dcr_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateRequest_ValidClient(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidAuthnMethod(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = "invalid_authn"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidScope(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ScopeIDs = "invalid_scope_id"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidPrivateKeyJWTSigAlg(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodPrivateKeyJWT
	client.TokenAuthnSigAlg = "invalid_sig_alg"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_JWKSRequiredForPrivateKeyJWT(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodPrivateKeyJWT
	client.JWKS = nil
	client.JWKSURI = ""

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_JWKSRequiredForSelfSignedTLS(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodSelfSignedTLS
	client.JWKS = nil
	client.JWKSURI = ""

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidSecretJWTSigAlg(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodSecretJWT
	client.TokenAuthnSigAlg = "invalid_sig_alg"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ValidTLSAuthn(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodTLS
	client.TLSSubDistinguishedName = "example"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_NoSubIdentifierForTLSAuthn(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodTLS

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_MoreThanOneSubIdentifierForTLSAuthn(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodTLS
	client.TLSSubDistinguishedName = "example"
	client.TLSSubAlternativeName = "example"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidGrantType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, "invalid_grant")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_NoneAuthnInvalidForClientCredentials(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.TokenAuthnMethod = goidc.AuthnMethodNone
	client.GrantTypes = append(client.GrantTypes, goidc.GrantClientCredentials)

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidAuthnForIntrospection(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenIntrospectionIsEnabled = true
	ctx.TokenIntrospectionAuthnMethods = []goidc.AuthnMethod{
		goidc.AuthnMethodSecretBasic,
	}
	client, _ := oidctest.NewClient(t)
	client.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidRedirectURI(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = append(client.RedirectURIs, "invalid")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_RedirectURIWithFragment(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = append(client.RedirectURIs, "https://example.com?param=value#fragment")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidResponseType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ResponseTypes = append(client.ResponseTypes, "invalid")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ImplicitGrantRequiredForImplicitResponseType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeIDToken}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_AuthzCodeGrantRequiredForCodeResponseType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ValidPublicSubjectIdentifierType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = goidc.SubIdentifierPublic

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ValidPairwiseSubjectIdentifierType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	client, _ := oidctest.NewClient(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal(client.RedirectURIs)
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}))
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.SectorIdentifierURI = server.URL

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ValidPairwiseSubjectIdentifierTypeWithNoSectorURI(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.RedirectURIs = []string{"https://example.com/test1", "https://example.com/test2"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidPairwiseSubjectIdentifierNoSectorURIAndRedirectURIsWithMultipleHosts(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.RedirectURIs = []string{"https://example1.com", "https://example.com2"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidRedirectURIsNotPresentWhenFetchingSectorIdentifierURI(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	client, _ := oidctest.NewClient(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal([]string{"https://random-redirect-uri-123.com"})
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}))
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.SectorIdentifierURI = server.URL

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidSubjectIdentifierType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = "invalid"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ValidAuthDetails(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1"}
	client, _ := oidctest.NewClient(t)
	client.AuthDetailTypes = append(client.AuthDetailTypes, "type1")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidAuthDetails(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1"}
	client, _ := oidctest.NewClient(t)
	client.AuthDetailTypes = append(client.AuthDetailTypes, "invalid")

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ValidCIBAPing(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
	client.CIBANotificationEndpoint = "https://example.com"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ValidCIBAPush(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePush
	client.CIBANotificationEndpoint = "https://example.com"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ValidCIBAPoll(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ValidCIBAJAR(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	ctx.CIBAJARIsEnabled = true
	ctx.CIBAJARSigAlgs = append(ctx.CIBAJARSigAlgs, goidc.RS256)
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
	client.CIBAJARSigAlg = goidc.RS256

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidCIBAJAR(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	ctx.CIBAJARIsEnabled = true
	ctx.CIBAJARSigAlgs = append(ctx.CIBAJARSigAlgs, goidc.RS256)
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
	client.CIBAJARSigAlg = goidc.PS256

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_ValidCIBAUserCode(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	ctx.CIBAUserCodeIsEnabled = true
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
	client.CIBAUserCodeIsEnabled = true

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidCIBADeliveryMode(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = "invalid_mode"

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_InvalidCIBAUserCode(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePing,
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	client, _ := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
	client.CIBAUserCodeIsEnabled = true

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

// RFC 8252 - OAuth 2.0 for Native Apps tests

func TestValidateRequest_RFC8252_NativeAppLoopbackIPv4(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://127.0.0.1/callback"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_RFC8252_NativeAppLoopbackIPv6(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://[::1]/callback"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_RFC8252_NativeAppPrivateUseURIScheme(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"com.example.app://callback"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_RFC8252_WebAppLoopbackRejected(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeWeb
	client.RedirectURIs = []string{"http://127.0.0.1/callback"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func TestValidateRequest_RFC8252_NativeAppNonLoopbackHTTPRejected(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://example.com/callback"}

	// When.
	err := dcr.Validate(ctx, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatalf("expected error but got none")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}
