package provider

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNewFAPI2ClientCredentialsOnly(t *testing.T) {
	jwk := oidctest.PrivatePS256JWK(t, "test_server_key", goidc.KeyUsageSignature)

	_, err := New(Config{
		Issuer: "https://example.com",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
	},
		WithProfile(goidc.ProfileFAPI2, WithProfileValidation()),
		WithClientCredentialsGrant(),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgES256}, WithDPoPRequired()),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNewFAPI2AuthorizationCodeStillRequiresPAR(t *testing.T) {
	jwk := oidctest.PrivatePS256JWK(t, "test_server_key", goidc.KeyUsageSignature)

	_, err := New(Config{
		Issuer: "https://example.com",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
	},
		WithProfile(goidc.ProfileFAPI2, WithProfileValidation()),
		WithAuthCodeGrant(
			AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}, WithPKCERequired()),
			WithIssuerResponseParameter(),
		),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgES256}, WithDPoPRequired()),
	)
	if err == nil || err.Error() != "[FAPI 2.0 5.3.1] pushed authorization request must be required" {
		t.Fatalf("New() error = %v, want missing PAR error", err)
	}
}

func TestNewFAPI2AuthorizationCodeRequiresCodeResponseTypeOnly(t *testing.T) {
	_, err := newFAPI2AuthorizationCodeProvider(
		t,
		[]goidc.ResponseType{goidc.ResponseType("code custom")},
		599,
	)
	if err == nil || err.Error() != "[FAPI 2.0 5.3.2.2] only the code response type may be enabled" {
		t.Fatalf("New() error = %v, want response type error", err)
	}
}

func TestNewFAPI2AuthorizationCodeRequiresPARLifetimeBelow600Seconds(t *testing.T) {
	if _, err := newFAPI2AuthorizationCodeProvider(
		t,
		[]goidc.ResponseType{goidc.ResponseTypeCode},
		599,
	); err != nil {
		t.Fatalf("New() with 599 second PAR lifetime error = %v", err)
	}

	_, err := newFAPI2AuthorizationCodeProvider(
		t,
		[]goidc.ResponseType{goidc.ResponseTypeCode},
		600,
	)
	if err == nil || err.Error() != "[FAPI 2.0 5.3.1] par request_uri lifetime must be less than 600 seconds" {
		t.Fatalf("New() with 600 second PAR lifetime error = %v, want lifetime error", err)
	}
}

func newFAPI2AuthorizationCodeProvider(
	t *testing.T,
	responseTypes []goidc.ResponseType,
	parLifetime int,
) (*Provider, error) {
	t.Helper()
	jwk := oidctest.PrivatePS256JWK(t, "test_server_key", goidc.KeyUsageSignature)
	return New(Config{
		Issuer: "https://example.com",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
	},
		WithProfile(goidc.ProfileFAPI2, WithProfileValidation()),
		WithAuthCodeGrant(
			AuthCodeGrantConfig{ResponseTypes: responseTypes},
			WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}, WithPKCERequired()),
			WithIssuerResponseParameter(),
			WithPAR(nil, WithPARRequired(), WithPARLifetime(parLifetime)),
		),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgES256}, WithDPoPRequired()),
	)
}
