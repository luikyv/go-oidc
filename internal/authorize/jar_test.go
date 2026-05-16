package authorize

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestJARFromRequestObject(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, string, *goidc.Client, request)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
	}{
		{
			name: "signed request object",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:         "https://server.example.com",
						JARIsEnabled: true,
						JARSigAlgs:   []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JWKS: &goidc.JSONWebKeySet{
							Keys: []goidc.JSONWebKey{privateJWK.Public()},
						},
					},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   client.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + 10,
					"client_id":         client.ID,
					"redirect_uri":      "https://example.com",
					"response_type":     goidc.ResponseTypeCode,
					"scope":             "scope scope2",
					"max_age":           600,
					"acr_values":        "0 1",
					"claims": map[string]any{
						"userinfo": map[string]any{
							"acr": map[string]any{
								"value": "0",
							},
						},
					},
				}, privateJWK)

				maxAge := 600
				want := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:     "https://example.com",
						ResponseType:    goidc.ResponseTypeCode,
						Scopes:          "scope scope2",
						MaxAuthnAgeSecs: &maxAge,
						ACRValues:       "0 1",
						Claims: &goidc.ClaimsObject{
							UserInfo: map[string]goidc.ClaimObjectInfo{
								"acr": {Value: "0"},
							},
						},
					},
				}
				return ctx, requestObject, client, want
			},
		},
		{
			name: "unsigned request object allowed",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:         "https://server.example.com",
						JARIsEnabled: true,
						JARSigAlgs:   []goidc.SignatureAlgorithm{goidc.None},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JARSigAlg: goidc.None,
					},
				}

				requestObject := joseutil.Unsigned(map[string]any{
					"client_id":     client.ID,
					"redirect_uri":  "https://example.com",
					"response_type": goidc.ResponseTypeCode,
					"scope":         "scope scope2",
					"max_age":       600,
					"acr_values":    "0 1",
					"claims": map[string]any{
						"userinfo": map[string]any{
							"acr": map[string]any{
								"value": "0",
							},
						},
					},
				}, nil)

				maxAge := 600
				want := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:     "https://example.com",
						ResponseType:    goidc.ResponseTypeCode,
						Scopes:          "scope scope2",
						MaxAuthnAgeSecs: &maxAge,
						ACRValues:       "0 1",
						Claims: &goidc.ClaimsObject{
							UserInfo: map[string]goidc.ClaimObjectInfo{
								"acr": {Value: "0"},
							},
						},
					},
				}
				return ctx, requestObject, client, want
			},
		},
		{
			name: "unsigned request object denied when none is not allowed",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:         "https://server.example.com",
						JARIsEnabled: true,
						JARSigAlgs:   []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JARSigAlg: goidc.SignatureAlgorithm(privateJWK.Algorithm),
					},
				}

				requestObject := joseutil.Unsigned(map[string]any{
					"client_id":     client.ID,
					"redirect_uri":  "https://example.com",
					"response_type": goidc.ResponseTypeCode,
					"scope":         "scope scope2",
				}, nil)

				return ctx, requestObject, client, request{}
			},
			wantErr:         goidc.ErrorCodeInvalidResquestObject,
			wantDescription: "invalid request object",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, requestObject, client, want := test.setup(t)

			// When.
			jar, err := jarFromRequestObject(ctx, requestObject, client)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(jar, want); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestJARFromRequestURI(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:                    "https://server.example.com",
			JARIsEnabled:            true,
			JARSigAlgs:              []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
			JARByReferenceIsEnabled: true,
			HTTPClientFunc: func(_ context.Context) *http.Client {
				return http.DefaultClient
			},
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	now := timeutil.TimestampNow()
	requestObject := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
		"scope":             "scope scope2",
		"max_age":           600,
		"acr_values":        "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}, privateJWK)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(requestObject)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	jar, err := jarFromRequestURI(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	maxAge := 600
	want := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:     "https://example.com",
			ResponseType:    goidc.ResponseTypeCode,
			Scopes:          "scope scope2",
			MaxAuthnAgeSecs: &maxAge,
			ACRValues:       "0 1",
			Claims: &goidc.ClaimsObject{
				UserInfo: map[string]goidc.ClaimObjectInfo{
					"acr": {Value: "0"},
				},
			},
		},
	}
	if diff := cmp.Diff(jar, want); diff != "" {
		t.Error(diff)
	}
}

func TestJARFromRequestURIErrors(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	t.Run("non-200 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()

		ctx := oidc.Context{
			Configuration: &oidc.Configuration{
				Host:                    "https://server.example.com",
				JARIsEnabled:            true,
				JARSigAlgs:              []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
				JARByReferenceIsEnabled: true,
				HTTPClientFunc: func(_ context.Context) *http.Client {
					return http.DefaultClient
				},
			},
			Request: &http.Request{Method: http.MethodPost},
		}

		_, err := jarFromRequestURI(ctx, server.URL, client)
		if err == nil {
			t.Fatal("expected error")
		}

		var oidcErr goidc.Error
		if !errors.As(err, &oidcErr) {
			t.Fatalf("invalid error type: %T", err)
		}
		if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
			t.Fatalf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
		}
		if oidcErr.Description != "invalid request_uri" {
			t.Fatalf("error description = %q, want %q", oidcErr.Description, "invalid request_uri")
		}
		if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "request_uri returned HTTP status 502" {
			t.Fatalf("wrapped error = %v, want %q", unwrapped, "request_uri returned HTTP status 502")
		}
	})
}
