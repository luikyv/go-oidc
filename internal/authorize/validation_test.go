package authorize

import (
	"errors"
	"slices"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateRequest(t *testing.T) {
	newValidRequest := func(client *goidc.Client) request {
		return request{
			AuthorizationParameters: goidc.AuthorizationParameters{
				RedirectURI:  client.RedirectURIs[0],
				ResponseType: goidc.ResponseTypeCode,
				ResponseMode: goidc.ResponseModeQuery,
				Scopes:       client.ScopeIDs,
				State:        "random_state",
				Nonce:        "random_nonce",
			},
		}
	}

	tests := []struct {
		name             string
		setup            func(*testing.T) (oidc.Context, *goidc.Client, request)
		wantErr          goidc.ErrorCode
		wantRedirectErr  bool
		wantNonRedirect  bool
		wantRedirectURIs []string
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, newValidRequest(client)
			},
		},
		{
			name: "invalid response type",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ResponseTypes = nil
				return ctx, client, newValidRequest(client)
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantRedirectErr: true,
		},
		{
			name: "invalid scope",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.Scopes = "invalid_scope"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidScope,
			wantRedirectErr: true,
		},
		{
			name: "invalid redirect uri",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.RedirectURI = "https://invalid.com"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "resource indicator",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.ResponseMode = ""
				req.Resources = []string{"https://resource.com"}
				return ctx, client, req
			},
		},
		{
			name: "resource indicator invalid resource",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.ResponseMode = ""
				req.Resources = []string{"https://invalid.com"}
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidTarget,
			wantRedirectErr: true,
		},
		{
			name: "redirect uri exact match",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "https://example.com/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri loopback ipv4 with port",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri loopback ipv6 with port",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://[::1]/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://[::1]:9000/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri non loopback native app keeps exact port match",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "https://example.com:444/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri loopback not registered",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri loopback non native app",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeWeb
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri private scheme",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"com.example.app://callback"}
				req := newValidRequest(client)
				req.RedirectURI = "com.example.app://callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri invalid uri",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "://invalid"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, client, req := test.setup(t)

			err := validateRequest(ctx, req, client)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				if test.wantRedirectErr {
					var redirectErr redirectionError
					if !errors.As(err, &redirectErr) {
						t.Fatalf("expected redirected error, got %T", err)
					}
					if redirectErr.Code() != test.wantErr {
						t.Fatalf("code = %s, want %s", redirectErr.Code(), test.wantErr)
					}
				}

				if test.wantNonRedirect {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) {
						t.Fatalf("expected OIDC error, got %T", err)
					}
					if oidcErr.Code != test.wantErr {
						t.Fatalf("code = %s, want %s", oidcErr.Code, test.wantErr)
					}
				}
			}

			if test.wantRedirectURIs != nil && !slices.Equal(client.RedirectURIs, test.wantRedirectURIs) {
				t.Fatalf("RedirectURIs = %v, want %v", client.RedirectURIs, test.wantRedirectURIs)
			}
		})
	}
}

func TestValidateRequestWithPAR(t *testing.T) {
	tests := []struct {
		name             string
		setup            func(*testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client)
		wantErr          goidc.ErrorCode
		wantRedirectURIs []string
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusPending,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow() + 10,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
		},
		{
			name: "unregistered redirect uri does not mutate client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.PARUnregisteredRedirectURIIsEnabled = true
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusPending,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow() + 10,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  "https://unregistered.example.com/callback",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
			wantRedirectURIs: []string{"https://example.com/callback"},
		},
		{
			name: "request uri can be reused while session is pending",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusPending,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow() + 10,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
		},
		{
			name: "request uri cannot be reused after session is resolved",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusSuccess,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow() + 10,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "expired request uri",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusPending,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow() - 1,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "request uri expires at current timestamp",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.AuthnSession, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				session := &goidc.AuthnSession{
					Status:    goidc.StatusPending,
					ClientID:  client.ID,
					ExpiresAt: timeutil.TimestampNow(),
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:       goidc.ScopeOpenID.ID,
						Nonce:        "random_nonce",
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
					},
				}
				return ctx, req, session, client
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, session, client := test.setup(t)

			err := validateRequestWithPAR(ctx, req, session, client)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected OIDC error, got %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("code = %s, want %s", oidcErr.Code, test.wantErr)
				}
			}

			if test.wantRedirectURIs != nil && !slices.Equal(client.RedirectURIs, test.wantRedirectURIs) {
				t.Fatalf("RedirectURIs = %v, want %v", client.RedirectURIs, test.wantRedirectURIs)
			}
		})
	}
}

func TestValidateRequestWithJAR(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, request, request, *goidc.Client)
		wantErr         goidc.ErrorCode
		wantNonRedirect bool
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
						Scopes:       client.ScopeIDs,
						Nonce:        "random_nonce",
					},
				}
				jar := request{
					ClientID:                client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{},
				}
				return ctx, req, jar, client
			},
		},
		{
			name: "invalid client id",
			setup: func(t *testing.T) (oidc.Context, request, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := request{ClientID: client.ID}
				jar := request{ClientID: "invalid_client_id"}
				return ctx, req, jar, client
			},
			wantErr:         goidc.ErrorCodeInvalidClient,
			wantNonRedirect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, jar, client := test.setup(t)

			err := validateRequestWithJAR(ctx, req, jar, client)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			if test.wantNonRedirect {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected OIDC error, got %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("code = %s, want %s", oidcErr.Code, test.wantErr)
				}
			}
		})
	}
}

func TestValidatePushedRequest(t *testing.T) {
	tests := []struct {
		name             string
		setup            func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr          bool
		wantRedirectURIs []string
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.RedirectURIs = append(client.RedirectURIs, "https://example.com")
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  "https://example.com",
						ResponseType: goidc.ResponseTypeCode,
						State:        "random_state",
					},
				}
				return ctx, req, client
			},
		},
		{
			name: "unregistered redirect uri does not mutate client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.PARUnregisteredRedirectURIIsEnabled = true
				client, _ := oidctest.NewClient(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  "https://unregistered.example.com/callback",
						ResponseType: goidc.ResponseTypeCode,
						State:        "random_state",
					},
				}
				return ctx, req, client
			},
			wantRedirectURIs: []string{"https://example.com/callback"},
		},
		{
			name: "fapi2 with redirect uri",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.Profile = goidc.ProfileFAPI2
				client, _ := oidctest.NewClient(t)
				client.RedirectURIs = append(client.RedirectURIs, "https://example.com")
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  "https://example.com",
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				return ctx, req, client
			},
		},
		{
			name: "fapi2 without redirect uri",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.Profile = goidc.ProfileFAPI2
				client, _ := oidctest.NewClient(t)
				client.RedirectURIs = append(client.RedirectURIs, "https://example.com")
				return ctx, request{}, client
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, client := test.setup(t)

			err := validatePushedRequest(ctx, req, client)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.wantRedirectURIs != nil && !slices.Equal(client.RedirectURIs, test.wantRedirectURIs) {
				t.Fatalf("RedirectURIs = %v, want %v", client.RedirectURIs, test.wantRedirectURIs)
			}
		})
	}
}
