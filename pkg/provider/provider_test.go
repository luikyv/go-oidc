package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		setup   func() (Config, []Option)
		want    oidc.Configuration
		ignores []string
	}{
		{
			name: "default",
			setup: func() (Config, []Option) {
				return Config{
					Issuer:      issuer,
					JWKS:        jwksFunc,
					IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				}, nil
			},
			want: oidc.Configuration{
				Profile:                  goidc.ProfileOpenID,
				Host:                     issuer,
				Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
				ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
				SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
				SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
				JWKSEndpoint:             defaultEndpointJSONWebKeySet,
				TokenEndpoint:            defaultEndpointToken,
				AuthorizationEndpoint:    defaultEndpointAuthorize,
				UserInfoEndpoint:         defaultEndpointUserInfo,
				AuthnMethods:             []goidc.AuthnMethod{goidc.AuthnMethodSecretPost},
				IDTokenDefaultSigAlg:     goidc.SigAlgRS256,
				IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
				JWTLifetimeSecs:          defaultJWTLifetimeSecs,
			},
			ignores: []string{
				"GrantManager",
				"OpaqueTokenManager",
				"JWKSFunc",
				"AuthSessionIDFunc",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"ClientCertFunc",
				"ConsumeJTIFunc",
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
				"OpenIDFedRequiredClientTrustMarksFunc",
				"OpenIDFedHandleClientFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
		{
			name: "with options",
			setup: func() (Config, []Option) {
				manager := storage.NewManager(100)
				return Config{
						Issuer:      issuer,
						JWKS:        jwksFunc,
						IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
					}, []Option{
						WithAuthCodeGrant(AuthCodeGrantConfig{
							Manager: manager,
							ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode, goidc.ResponseTypeToken,
								goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken, goidc.ResponseTypeCodeAndIDToken,
								goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken},
						},
							WithPAR(manager),
							WithJAR([]goidc.SignatureAlgorithm{goidc.SigAlgRS256}, WithJAREncryption(
								[]goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
								[]goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
							)),
							WithJARM([]goidc.SignatureAlgorithm{goidc.SigAlgRS256}),
							WithFormPostResponseMode(),
						),
						WithCIBAGrant(CIBAGrantConfig{
							Manager:       manager,
							DeliveryModes: []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll},
						},
							WithCIBASessionHandler(nil),
						),
						WithPrivateKeyJWTAuthn(goidc.SigAlgRS256),
						WithSecretJWTAuthn(goidc.SigAlgHS256),
						WithDCR(manager),
						WithTokenIntrospection(nil),
						WithTokenRevocation(nil),
						WithUserInfoSignatureAlgs(goidc.SigAlgPS256),
						WithUserInfoEncryption(
							[]goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
							[]goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
						),
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
				JWKSEndpoint:             defaultEndpointJSONWebKeySet,
				TokenEndpoint:            defaultEndpointToken,
				AuthorizationEndpoint:    defaultEndpointAuthorize,
				UserInfoEndpoint:         defaultEndpointUserInfo,
				UserInfoDefaultSigAlg:    goidc.SigAlgPS256,
				UserInfoSigAlgs:          []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
				IDTokenDefaultSigAlg:     goidc.SigAlgRS256,
				IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
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
				AuthnMethods:                    []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
				AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
				DCREnabled:                      true,
				DCREndpoint:                     defaultEndpointDynamicClient,
				PAREnabled:                      true,
				PAREndpoint:                     defaultEndpointPushedAuthorizationRequest,
				PARLifetimeSecs:                 defaultPARLifetimeSecs,
				JAREnabled:                      true,
				JARSigAlgs:                      []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				JAREncEnabled:                   true,
				JARKeyEncAlgs:                   []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
				JARContentEncAlgs:               []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
				JARMEnabled:                     true,
				JARMSigAlgDefault:               goidc.SigAlgRS256,
				JARMSigAlgs:                     []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
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
				TokenIntrospectionEnabled:      true,
				TokenIntrospectionEndpoint:     defaultEndpointTokenIntrospection,
				TokenRevocationEnabled:         true,
				TokenRevocationEndpoint:        defaultEndpointTokenRevocation,
				CIBAProfile:                    goidc.CIBAProfileOpenID,
				CIBATokenDeliveryModes:         []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll},
				CIBAEndpoint:                   defaultEndpointCIBA,
				CIBADefaultSessionLifetimeSecs: 60,
				CIBAPollingIntervalSecs:        5,
				UserInfoEncEnabled:             true,
				UserInfoKeyEncAlgs:             []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
				UserInfoContentEncAlgs:         []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
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
				"OpaqueTokenManager",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"ClientCertFunc",
				"JWKSFunc",
				"ConsumeJTIFunc",
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
				"OpenIDFedRequiredClientTrustMarksFunc",
				"OpenIDFedHandleClientFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, opts := test.setup()

			op, err := New(cfg, opts...)
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

func TestNew_DefaultsVCISelfBatchSize(t *testing.T) {
	p, err := New(Config{
		Issuer:      "https://example.com",
		JWKS:        func(context.Context) (goidc.JSONWebKeySet, error) { return goidc.JSONWebKeySet{}, nil },
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
	}, WithVCI(WithVCISelf(nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if p.config.VCISelfBatchSize != 1 {
		t.Fatalf("VCISelfBatchSize = %d, want 1", p.config.VCISelfBatchSize)
	}
	if p.config.VCISelfCredentialEndpoint != "/credential" {
		t.Fatalf("VCISelfCredentialEndpoint = %q, want /credential", p.config.VCISelfCredentialEndpoint)
	}
}

func TestNew_DefaultsVCISelfNotification(t *testing.T) {
	p, err := New(Config{
		Issuer:      "https://example.com",
		JWKS:        func(context.Context) (goidc.JSONWebKeySet, error) { return goidc.JSONWebKeySet{}, nil },
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
	}, WithVCI(WithVCISelf(nil, WithVCISelfNotification(nil, func(context.Context, *goidc.VCNotification, goidc.VCNotificationEvent) error {
		return nil
	}))))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if p.config.VCISelfNotificationEndpoint != "/notification" {
		t.Fatalf("VCISelfNotificationEndpoint = %q, want /notification", p.config.VCISelfNotificationEndpoint)
	}
	if p.config.VCISelfNotificationIDFunc == nil {
		t.Fatal("VCISelfNotificationIDFunc must be set")
	}
	if p.config.VCISelfNotificationManager == nil {
		t.Fatal("VCISelfNotificationManager must be set")
	}
}

func TestDefaultHTTPClientFuncDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	resp, err := defaultHTTPClientFunc(context.Background()).Get(source.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Fatal("default HTTP client followed redirect")
	}
}

func TestNew_ValidationErrors(t *testing.T) {
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name:    "jar by-reference unregistered uris require jar by-reference",
			opts:    []Option{Option(WithJARByReferenceUnregisteredURIs())},
			wantErr: "jar by-reference unregistered uris cannot be enabled without jar by-reference",
		},
		{
			name: "dcr secret lifetime requires secret client auth",
			opts: []Option{
				WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
				WithDCR(nil, WithDCRSecretLifetime(300)),
			},
			wantErr: "dcr secret lifetime requires a secret-based token authentication method",
		},
		{
			name: "dcr secret rotation requires secret client auth",
			opts: []Option{
				WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
				WithDCR(nil, WithDCRSecretRotation()),
			},
			wantErr: "dcr secret rotation requires a secret-based token authentication method",
		},
		{
			name: "client resolver and dcr are mutually exclusive",
			opts: []Option{
				WithClientResolver(func(context.Context, string) (*goidc.Client, error) {
					return nil, goidc.ErrNotFound
				}),
				WithDCR(nil),
			},
			wantErr: "client resolver cannot be combined with dynamic client registration",
		},
		{
			name: "client resolver and federation are mutually exclusive",
			opts: []Option{
				WithClientResolver(func(context.Context, string) (*goidc.Client, error) {
					return nil, goidc.ErrNotFound
				}),
				WithOpenIDFederation(OpenIDFedConfig{
					JWKSFunc:       jwksFunc,
					SigAlg:         goidc.SigAlgRS256,
					AuthorityHints: []string{"https://authority.example.com"},
					TrustedAnchors: []string{"https://trust-anchor.example.com"},
				}),
			},
			wantErr: "client resolver cannot be combined with OpenID Federation",
		},
		{
			name: "dc sd-jwt credential configuration requires type",
			opts: []Option{
				WithVCI(WithVCISelf([]goidc.VCConfiguration{
					{
						ID:     "identity",
						Format: goidc.VCFormatDCSDJWT,
					},
				}, WithVCISelfIssuer("https://credential-issuer.example.com"))),
			},
			wantErr: "credential configuration \"identity\" requires Type when Format is \"dc+sd-jwt\"",
		},
		{
			name: "dc sd-jwt credential configuration requires self jwt issuer",
			opts: []Option{
				WithVCI(WithVCISelf([]goidc.VCConfiguration{
					{
						ID:     "identity",
						Format: goidc.VCFormatDCSDJWT,
						Type:   "IdentityCredential",
					},
				}, WithVCISelfIssuer("https://credential-issuer.example.com"))),
			},
			wantErr: "credential configuration \"identity\" with Format \"dc+sd-jwt\" requires WithVCISelfJWTIssuer",
		},
		{
			name: "self jwt issuer requires jwks source",
			opts: []Option{
				WithVCI(WithVCISelf(nil,
					WithVCISelfIssuer("https://credential-issuer.example.com"),
					WithVCISelfJWTIssuer(),
				)),
			},
			wantErr: "WithVCISelfJWTIssuer requires either JWKS or JWKS URI",
		},
		{
			name: "self jwt issuer requires one jwks source",
			opts: []Option{
				WithVCI(WithVCISelf(nil,
					WithVCISelfIssuer("https://credential-issuer.example.com"),
					WithVCISelfJWTIssuer(
						WithVCISelfJWTIssuerJWKS(jwksFunc),
						WithVCISelfJWTIssuerJWKSURI("https://credential-issuer.example.com/jwks"),
					),
				)),
			},
			wantErr: "WithVCISelfJWTIssuer requires either JWKS or JWKS URI, not both",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{Issuer: issuer, JWKS: jwksFunc, IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256}}, test.opts...)
			if err == nil {
				t.Fatal("New() error = nil, want non-nil")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("New() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

func TestClientResolverDoesNotExposeDynamicRegistration(t *testing.T) {
	op, err := New(Config{
		Issuer: "https://example.com",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
	}, WithClientResolver(func(context.Context, string) (*goidc.Client, error) {
		return nil, goidc.ErrNotFound
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	metadataResponse := httptest.NewRecorder()
	op.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want %d", metadataResponse.Code, http.StatusOK)
	}
	var metadata map[string]any
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if _, advertised := metadata["registration_endpoint"]; advertised {
		t.Fatal("registration_endpoint advertised with only a client resolver configured")
	}

	registrationResponse := httptest.NewRecorder()
	op.Handler().ServeHTTP(registrationResponse, httptest.NewRequest(http.MethodPost, defaultEndpointDynamicClient, nil))
	if registrationResponse.Code != http.StatusNotFound {
		t.Fatalf("registration status = %d, want %d", registrationResponse.Code, http.StatusNotFound)
	}
}

func TestMakeToken(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	jwk := oidctest.PrivateRS256JWK(t, "test_key", goidc.KeyUsageSignature)
	op, _ := New(
		Config{
			Issuer: issuer,
			JWKS: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
			},
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
		WithTokenOptions(func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
			return goidc.NewJWTTokenOptions(goidc.SigAlgRS256, 60)
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
			return k == "jti" || k == "grant_id"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}
