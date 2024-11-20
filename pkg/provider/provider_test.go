package provider

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNew(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	var jwksFunc goidc.PrivateJWKSFunc = func(ctx context.Context) (jose.JSONWebKeySet, error) {
		return jose.JSONWebKeySet{}, nil
	}

	// When.
	op, err := New(goidc.ProfileOpenID, issuer, jwksFunc)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		*op.config,
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
			EndpointWellKnown:        defaultEndpointWellKnown,
			EndpointJWKS:             defaultEndpointJSONWebKeySet,
			EndpointToken:            defaultEndpointToken,
			EndpointAuthorize:        defaultEndpointAuthorize,
			EndpointUserInfo:         defaultEndpointUserInfo,
			UserDefaultSigAlg:        jose.RS256,
			UserSigAlgs:              []jose.SignatureAlgorithm{jose.RS256},
			IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
			JWTLifetimeSecs:          defaultJWTLifetimeSecs,
		},
		cmpopts.IgnoreFields(
			oidc.Configuration{},
			"ClientManager",
			"AuthnSessionManager",
			"GrantSessionManager",
			"PrivateJWKSFunc",
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
	var jwksFunc goidc.PrivateJWKSFunc = func(ctx context.Context) (jose.JSONWebKeySet, error) {
		return jose.JSONWebKeySet{}, nil
	}

	// When.
	op, err := New(
		goidc.ProfileOpenID,
		issuer,
		jwksFunc,
		WithAuthorizationCodeGrant(),
		WithImplicitGrant(),
		WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT, goidc.ClientAuthnSecretJWT),
		WithDCR(nil, nil),
		WithPAR(0),
		WithJAR(jose.RS256),
		WithJAREncryption(jose.RSA_OAEP),
		WithJARM(jose.RS256),
		WithTokenIntrospection(nil, goidc.ClientAuthnPrivateKeyJWT),
		WithTokenRevocation(nil, goidc.ClientAuthnPrivateKeyJWT),
		WithCIBAGrant(nil, nil, goidc.CIBATokenDeliveryModePoll),
		WithUserInfoEncryption(jose.RSA_OAEP),
	)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		*op.config,
		oidc.Configuration{
			Profile:                  goidc.ProfileOpenID,
			Host:                     issuer,
			Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
			AuthnSessionTimeoutSecs:  defaultAuthnSessionTimeoutSecs,
			ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
			DefaultSubIdentifierType: goidc.SubIdentifierPublic,
			SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
			EndpointWellKnown:        defaultEndpointWellKnown,
			EndpointJWKS:             defaultEndpointJSONWebKeySet,
			EndpointToken:            defaultEndpointToken,
			EndpointAuthorize:        defaultEndpointAuthorize,
			EndpointUserInfo:         defaultEndpointUserInfo,
			UserDefaultSigAlg:        jose.RS256,
			UserSigAlgs:              []jose.SignatureAlgorithm{jose.RS256},
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
			TokenAuthnMethods:           []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT, goidc.ClientAuthnSecretJWT},
			PrivateKeyJWTSigAlgs:        []jose.SignatureAlgorithm{jose.RS256},
			ClientSecretJWTSigAlgs:      []jose.SignatureAlgorithm{jose.HS256},
			DCRIsEnabled:                true,
			EndpointDCR:                 defaultEndpointDynamicClient,
			PARIsEnabled:                true,
			EndpointPushedAuthorization: defaultEndpointPushedAuthorizationRequest,
			JARIsEnabled:                true,
			JARSigAlgs:                  []jose.SignatureAlgorithm{jose.RS256},
			JAREncIsEnabled:             true,
			JARKeyEncAlgs:               []jose.KeyAlgorithm{jose.RSA_OAEP},
			JARContentEncAlgs:           []jose.ContentEncryption{jose.A128CBC_HS256},
			JARMIsEnabled:               true,
			JARMDefaultSigAlg:           jose.RS256,
			JARMSigAlgs:                 []jose.SignatureAlgorithm{jose.RS256},
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
			TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT},
			EndpointIntrospection:          defaultEndpointTokenIntrospection,
			TokenRevocationIsEnabled:       true,
			TokenRevocationAuthnMethods:    []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT},
			EndpointTokenRevocation:        defaultEndpointTokenRevocation,
			CIBAIsEnabled:                  true,
			CIBATokenDeliveryModels:        []goidc.CIBATokenDeliveryMode{goidc.CIBATokenDeliveryModePoll},
			EndpointCIBA:                   defaultEndpointCIBA,
			CIBADefaultSessionLifetimeSecs: 60,
			CIBAPollingIntervalSecs:        5,
			UserEncIsEnabled:               true,
			UserKeyEncAlgs:                 []jose.KeyAlgorithm{jose.RSA_OAEP},
			UserDefaultContentEncAlg:       jose.A128CBC_HS256,
			UserContentEncAlgs:             []jose.ContentEncryption{jose.A128CBC_HS256},
		},
		cmpopts.IgnoreFields(
			oidc.Configuration{},
			"ClientManager",
			"AuthnSessionManager",
			"GrantSessionManager",
			"PrivateJWKSFunc",
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
