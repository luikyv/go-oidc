package provider

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNew(t *testing.T) {
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	tests := []struct {
		name    string
		setup   func() (goidc.GrantManager, []Option)
		want    oidc.Configuration
		ignores []string
	}{
		{
			name: "default",
			setup: func() (goidc.GrantManager, []Option) {
				return storage.NewManager(100), nil
			},
			want: oidc.Configuration{
				Profile: goidc.ProfileOpenID,
				Host:    issuer,
				Scopes:  []goidc.Scope{goidc.ScopeOpenID},
				ResponseModes: []goidc.ResponseMode{
					goidc.ResponseModeQuery,
					goidc.ResponseModeFragment,
				},
				ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
				SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
				SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
				WellKnownEndpoint:        defaultEndpointWellKnown,
				JWKSEndpoint:             defaultEndpointJSONWebKeySet,
				TokenEndpoint:            defaultEndpointToken,
				AuthorizationEndpoint:    defaultEndpointAuthorize,
				UserInfoEndpoint:         defaultEndpointUserInfo,
				TokenAuthnMethodDefault:  goidc.AuthnMethodSecretPost,
				TokenAuthnMethods:        []goidc.AuthnMethod{goidc.AuthnMethodSecretPost},
				IDTokenDefaultSigAlg:     goidc.RS256,
				IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.RS256},
				IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
				JWTLifetimeSecs:          defaultJWTLifetimeSecs,
			},
			ignores: []string{
				"GrantManager",
				"JWKSFunc",
				"AuthSessionIDFunc",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"ClientCertFunc",
				"CheckJTIFunc",
				"TokenIntrospectionIsClientAllowedFunc",
				"TokenRevocationIsClientAllowedFunc",
				"HandleErrorFunc",
				"RARValidateDetailFunc",
				"RefreshTokenShouldIssueFunc",
				"HandleGrantFunc",
				"HandleTokenFunc",
				"IDTokenClaimsFunc",
				"UserInfoClaimsFunc",
				"TokenClaimsFunc",
				"PairwiseSubjectFunc",
				"OpenIDFedRequiredTrustMarksFunc",
				"OpenIDFedHandleClientFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
		{
			name: "with options",
			setup: func() (goidc.GrantManager, []Option) {
				manager := storage.NewManager(100)
				return manager, []Option{
					WithAuthCodeGrant(manager, goidc.ResponseTypeCode, goidc.ResponseTypeToken,
						goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken, goidc.ResponseTypeCodeAndIDToken,
						goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken),
					WithCIBAGrant(manager, goidc.CIBADeliveryModePoll),
					WithTokenAuthnMethods(goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT),
					WithDCR(manager),
					WithPAR(manager),
					WithJAR(goidc.RS256),
					WithJAREncryption(goidc.RSA_OAEP),
					WithJARM(goidc.RS256),
					WithFormPostResponseMode(),
					WithTokenIntrospection(nil),
					WithTokenRevocation(nil),
					WithCIBAHandleSessionFunc(nil),
					WithUserInfoSignatureAlgs(goidc.PS256),
					WithUserInfoEncryption(goidc.RSA_OAEP),
				}
			},
			want: oidc.Configuration{
				Profile:                  goidc.ProfileOpenID,
				Host:                     issuer,
				Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
				AuthTimeoutSecs:          defaultAuthnSessionTimeoutSecs,
				ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
				SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
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
					goidc.GrantCIBA,
					goidc.GrantImplicit,
				},
				ResponseTypes: []goidc.ResponseType{
					goidc.ResponseTypeCode,
					goidc.ResponseTypeToken,
					goidc.ResponseTypeIDToken,
					goidc.ResponseTypeIDTokenAndToken,
					goidc.ResponseTypeCodeAndIDToken,
					goidc.ResponseTypeCodeAndToken,
					goidc.ResponseTypeCodeAndIDTokenAndToken,
				},
				TokenAuthnMethodDefault:        goidc.AuthnMethodPrivateKeyJWT,
				TokenAuthnMethods:              []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
				TokenAuthnPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.RS256},
				TokenAuthnSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.HS256},
				DCRIsEnabled:                   true,
				DCREndpoint:                    defaultEndpointDynamicClient,
				PARIsEnabled:                   true,
				PAREndpoint:                    defaultEndpointPushedAuthorizationRequest,
				PARLifetimeSecs:                defaultPARLifetimeSecs,
				JARIsEnabled:                   true,
				JARSigAlgs:                     []goidc.SignatureAlgorithm{goidc.RS256},
				JAREncIsEnabled:                true,
				JARKeyEncAlgs:                  []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
				JARContentEncAlgs:              []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
				JARMIsEnabled:                  true,
				JARMSigAlgDefault:              goidc.RS256,
				JARMSigAlgs:                    []goidc.SignatureAlgorithm{goidc.RS256},
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
				TokenIntrospectionEndpoint:     defaultEndpointTokenIntrospection,
				TokenRevocationIsEnabled:       true,
				TokenRevocationEndpoint:        defaultEndpointTokenRevocation,
				CIBAProfile:                    goidc.CIBAProfileOpenID,
				CIBATokenDeliveryModes:         []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll},
				CIBAEndpoint:                   defaultEndpointCIBA,
				CIBADefaultSessionLifetimeSecs: 60,
				CIBAPollingIntervalSecs:        5,
				UserInfoEncIsEnabled:           true,
				UserInfoKeyEncAlgs:             []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
				UserInfoDefaultContentEncAlg:   goidc.A128CBC_HS256,
				UserInfoContentEncAlgs:         []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
				AuthCodeLifetimeSecs:           60,
			},
			ignores: []string{
				"AuthManager",
				"AuthCodeFunc",
				"AuthSessionIDFunc",
				"PARIDFunc",
				"PARHandleSessionFunc",
				"DCRManager",
				"DCRClientIDFunc",
				"DCRHandleClientFunc",
				"DCRRegistrationTokenFunc",
				"DCRValidateInitialTokenFunc",
				"PARManager",
				"CIBAIDFunc",
				"CIBAHandleSessionFunc",
				"CIBAManager",
				"GrantManager",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"ClientCertFunc",
				"JWKSFunc",
				"CheckJTIFunc",
				"TokenIntrospectionIsClientAllowedFunc",
				"TokenRevocationIsClientAllowedFunc",
				"HandleErrorFunc",
				"RARValidateDetailFunc",
				"RefreshTokenShouldIssueFunc",
				"HandleGrantFunc",
				"HandleTokenFunc",
				"IDTokenClaimsFunc",
				"UserInfoClaimsFunc",
				"TokenClaimsFunc",
				"PairwiseSubjectFunc",
				"OpenIDFedRequiredTrustMarksFunc",
				"OpenIDFedHandleClientFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, opts := test.setup()

			op, err := New(issuer, manager, jwksFunc, opts...)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(
				op.config,
				test.want,
				cmpopts.IgnoreFields(oidc.Configuration{}, test.ignores...),
				cmpopts.IgnoreFields(goidc.Scope{}, "Matches"),
			); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestNew_JARByReferenceUnregisteredURIsRequireJARByReference(t *testing.T) {
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	_, err := New(
		issuer,
		storage.NewManager(100),
		jwksFunc,
		WithJARByReferenceUnregisteredURIs(),
	)
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
	if got, want := err.Error(), "jar by-reference unregistered uris cannot be enabled without jar by-reference"; got != want {
		t.Fatalf("New() error = %q, want %q", got, want)
	}
}

func TestMakeToken(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	jwk := oidctest.PrivateRS256JWK(t, "test_key", goidc.KeyUsageSignature)
	op, _ := New(
		issuer,
		storage.NewManager(100),
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
		ID:        grantSession.ID,
		CreatedAt: grantSession.CreatedAt,
		Subject:   issuer,
		ClientID:  issuer,
		Scopes:    "openid",
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
