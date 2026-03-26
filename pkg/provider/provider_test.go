package provider

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNew(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	// When.
	op, err := New(goidc.ProfileOpenID, issuer, jwksFunc)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		op.config,
		oidc.Configuration{
			Profile: goidc.ProfileOpenID,
			Host:    issuer,
			Scopes:  []goidc.Scope{goidc.ScopeOpenID},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			AuthnSessionTimeoutSecs:  defaultAuthnSessionTimeoutSecs,
			ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
			DefaultSubIdentifierType: goidc.SubIdentifierPublic,
			SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
			WellKnownEndpoint:        defaultEndpointWellKnown,
			JWKSEndpoint:             defaultEndpointJSONWebKeySet,
			TokenEndpoint:            defaultEndpointToken,
			AuthorizationEndpoint:    defaultEndpointAuthorize,
			UserInfoEndpoint:         defaultEndpointUserInfo,
			IDTokenDefaultSigAlg:     goidc.RS256,
			IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.RS256},
			IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
			JWTLifetimeSecs:          defaultJWTLifetimeSecs,
		},
		cmpopts.IgnoreFields(
			oidc.Configuration{},
			"ClientManager",
			"AuthnSessionManager",
			"GrantManager",
			"TokenManager",
			"JWKSFunc",
			"TokenOptionsFunc",
		),
		cmpopts.IgnoreFields(
			goidc.Scope{},
			"Matches",
		),
	); diff != "" {
		t.Error(diff)
	}
}

func TestNew_WithOptions(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	// When.
	op, err := New(
		goidc.ProfileOpenID,
		issuer,
		jwksFunc,
		WithGrantTypes(goidc.GrantAuthorizationCode, goidc.GrantImplicit, goidc.GrantCIBA),
		WithTokenAuthnMethods(goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT),
		WithDCR(),
		WithPAR(),
		WithJAR(goidc.RS256),
		WithJAREncryption(goidc.RSA_OAEP),
		WithJARM(goidc.RS256),
		WithTokenIntrospection(nil, goidc.AuthnMethodPrivateKeyJWT),
		WithTokenRevocation(nil, goidc.AuthnMethodPrivateKeyJWT),
		WithCIBAHandleSessionFunc(nil),
		WithCIBADeliveryModes(goidc.CIBADeliveryModePoll),
		WithUserInfoSignatureAlgs(goidc.PS256),
		WithUserInfoEncryption(goidc.RSA_OAEP),
	)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		op.config,
		oidc.Configuration{
			Profile:                  goidc.ProfileOpenID,
			Host:                     issuer,
			Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
			AuthnSessionTimeoutSecs:  defaultAuthnSessionTimeoutSecs,
			ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
			DefaultSubIdentifierType: goidc.SubIdentifierPublic,
			SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
			WellKnownEndpoint:        defaultEndpointWellKnown,
			JWKSEndpoint:             defaultEndpointJSONWebKeySet,
			TokenEndpoint:            defaultEndpointToken,
			AuthorizationEndpoint:    defaultEndpointAuthorize,
			UserInfoEndpoint:         defaultEndpointUserInfo,
			UserInfoDefaultSigAlg:    goidc.PS256,
			UserInfoSigAlgs:          []goidc.SignatureAlgorithm{goidc.PS256},
			IDTokenDefaultSigAlg:     goidc.RS256,
			IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.RS256},
			IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
			JWTLifetimeSecs:          defaultJWTLifetimeSecs,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantImplicit,
				goidc.GrantCIBA,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode, goidc.ResponseTypeToken,
				goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken, goidc.ResponseTypeCodeAndIDToken,
				goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken},
			TokenAuthnMethods:      []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
			PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.RS256},
			ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
			DCRIsEnabled:           true,
			DCREndpoint:            defaultEndpointDynamicClient,
			PARIsEnabled:           true,
			PAREndpoint:            defaultEndpointPushedAuthorizationRequest,
			PARLifetimeSecs:        defaultPARLifetimeSecs,
			JARIsEnabled:           true,
			JARSigAlgs:             []goidc.SignatureAlgorithm{goidc.RS256},
			JAREncIsEnabled:        true,
			JARKeyEncAlgs:          []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
			JARContentEncAlgs:      []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
			JARMIsEnabled:          true,
			JARMDefaultSigAlg:      goidc.RS256,
			JARMSigAlgs:            []goidc.SignatureAlgorithm{goidc.RS256},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
				goidc.ResponseModeJWT,
				goidc.ResponseModeQueryJWT,
				goidc.ResponseModeFragmentJWT,
				goidc.ResponseModeFormPostJWT,
			},
			JARMLifetimeSecs:               defaultJWTLifetimeSecs,
			TokenIntrospectionIsEnabled:    true,
			TokenIntrospectionAuthnMethods: []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
			IntrospectionEndpoint:          defaultEndpointTokenIntrospection,
			TokenRevocationIsEnabled:       true,
			TokenRevocationAuthnMethods:    []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
			TokenRevocationEndpoint:        defaultEndpointTokenRevocation,
			CIBAProfile:                    goidc.CIBAProfileOpenID,
			CIBATokenDeliveryModels:        []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll},
			CIBAEndpoint:                   defaultEndpointCIBA,
			CIBADefaultSessionLifetimeSecs: 60,
			CIBAPollingIntervalSecs:        5,
			UserInfoEncIsEnabled:           true,
			UserInfoKeyEncAlgs:             []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
			UserInfoDefaultContentEncAlg:   goidc.A128CBC_HS256,
			UserInfoContentEncAlgs:         []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
			AuthorizationCodeLifetimeSecs:  60,
		},
		cmpopts.IgnoreFields(
			oidc.Configuration{},
			"ClientManager",
			"AuthnSessionManager",
			"GrantManager",
			"TokenManager",
			"JWKSFunc",
			"TokenOptionsFunc",
		),
		cmpopts.IgnoreFields(
			goidc.Scope{},
			"Matches",
		),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeToken(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	jwk := oidctest.PrivateRS256JWK(t, "test_key", goidc.KeyUsageSignature)
	op, _ := New(
		goidc.ProfileOpenID,
		issuer,
		func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{jwk},
			}, nil
		},
		WithTokenOptions(func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
			return goidc.NewJWTTokenOptions(goidc.RS256, 60)
		}),
	)

	ctx := context.Background()
	oidcCtx := oidc.NewContext(ctx, &op.config)
	grant := &goidc.Grant{
		Type:     goidc.GrantClientCredentials,
		ClientID: issuer,
		Subject:  issuer,
		Scopes:   "openid",
	}

	// When.
	tkn, err := op.MakeToken(ctx, grant)

	// Then.
	if err != nil {
		t.Error(err)
	}

	grantSessions := oidctest.Grants(t, oidcCtx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]
	wantedSession := goidc.Grant{
		ID:                 grantSession.ID,
		CreatedAtTimestamp: grantSession.CreatedAtTimestamp,
		ExpiresAtTimestamp: grantSession.ExpiresAtTimestamp,
		Type:               goidc.GrantClientCredentials,
		Subject:            issuer,
		ClientID:           issuer,
		Scopes:             "openid",
	}
	if diff := cmp.Diff(
		*grantSession,
		wantedSession,
		cmpopts.EquateApprox(0, 1),
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tkn, jwk)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       issuer,
		"sub":       issuer,
		"client_id": issuer,
		"scope":     grant.Scopes,
		"exp":       float64(now + 60),
		"iat":       float64(now),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

}
