package vc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRegisterHandlers_Disabled(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "offers disabled",
			method: http.MethodGet,
			path:   "/credential_offer/id",
		},
		{
			name:   "jwt issuer metadata disabled",
			method: http.MethodGet,
			path:   "/.well-known/jwt-vc-issuer",
		},
		{
			name:   "deferred credential disabled",
			method: http.MethodPost,
			path:   "/deferred_credential",
		},
		{
			name:   "notification disabled",
			method: http.MethodPost,
			path:   "/notification",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterHandlers(mux, &oidc.Configuration{
				VCISelfEnabled:            true,
				VCISelfCredentialEndpoint: "/credential",
			})

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))

			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
			}
		})
	}
}

func TestHandleNotification(t *testing.T) {
	tests := []struct {
		name              string
		body              map[string]string
		wantStatus        int
		wantNotification  *goidc.VCNotification
		notification      *goidc.VCNotification
		wantEvent         goidc.VCNotificationEvent
		wantHandlerCalled bool
	}{
		{
			name: "success",
			body: map[string]string{
				"notification_id":   "notification_id",
				"event":             string(goidc.VCNotificationEventCredentialFailure),
				"event_description": "Could not store the Credential.",
				"ignored":           "ignored",
			},
			wantStatus: http.StatusNoContent,
			wantNotification: &goidc.VCNotification{
				ID:                        "notification_id",
				GrantID:                   "grant",
				ClientID:                  "client",
				CredentialConfigurationID: "identity",
				CreatedAt:                 1,
			},
			notification: &goidc.VCNotification{
				ID:                        "notification_id",
				GrantID:                   "grant",
				ClientID:                  "client",
				CredentialConfigurationID: "identity",
				CreatedAt:                 1,
			},
			wantEvent: goidc.VCNotificationEvent{
				Type:        goidc.VCNotificationEventCredentialFailure,
				Description: "Could not store the Credential.",
			},
			wantHandlerCalled: true,
		},
		{
			name: "invalid description",
			body: map[string]string{
				"notification_id":   "notification_id",
				"event":             string(goidc.VCNotificationEventCredentialAccepted),
				"event_description": "not ascii: café",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown notification id",
			body: map[string]string{
				"notification_id": "notification_id",
				"event":           string(goidc.VCNotificationEventCredentialAccepted),
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "grant mismatch",
			body: map[string]string{
				"notification_id": "notification_id",
				"event":           string(goidc.VCNotificationEventCredentialAccepted),
			},
			notification: &goidc.VCNotification{
				ID:                        "notification_id",
				GrantID:                   "other_grant",
				ClientID:                  "client",
				CredentialConfigurationID: "identity",
				CreatedAt:                 1,
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got *goidc.VCNotification
			var gotEvent goidc.VCNotificationEvent
			handlerCalled := false
			ctx := newCredentialIssueContext(t, goidc.NewScope("identity"))
			ctx.VCISelfEnabled = true
			ctx.VCISelfCredentialEndpoint = "/credential"
			ctx.VCISelfNotificationEnabled = true
			ctx.VCISelfNotificationEndpoint = "/notification"
			ctx.VCISelfNotificationManager = oidctest.Manager(t, ctx)
			ctx.VCISelfNotificationHandleFunc = func(_ context.Context, notification *goidc.VCNotification, event goidc.VCNotificationEvent) error {
				handlerCalled = true
				got = notification
				gotEvent = event
				return nil
			}
			if test.notification != nil {
				if err := ctx.VCSaveNotification(test.notification); err != nil {
					t.Fatalf("VCSaveNotification() error = %v", err)
				}
			}

			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			body, _ := json.Marshal(test.body)
			req := httptest.NewRequest(http.MethodPost, "/notification", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer access_token")

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if handlerCalled != test.wantHandlerCalled {
				t.Fatalf("handler called = %t, want %t", handlerCalled, test.wantHandlerCalled)
			}
			if test.wantNotification == nil {
				return
			}
			if got == nil {
				t.Fatal("notification must be passed to handler")
			}
			if got.ID != test.wantNotification.ID {
				t.Fatalf("notification_id = %q, want %q", got.ID, test.wantNotification.ID)
			}
			if got.GrantID != test.wantNotification.GrantID {
				t.Fatalf("grant_id = %q, want %q", got.GrantID, test.wantNotification.GrantID)
			}
			if got.ClientID != test.wantNotification.ClientID {
				t.Fatalf("client_id = %q, want %q", got.ClientID, test.wantNotification.ClientID)
			}
			if got.CredentialConfigurationID != test.wantNotification.CredentialConfigurationID {
				t.Fatalf("credential_configuration_id = %q, want %q", got.CredentialConfigurationID, test.wantNotification.CredentialConfigurationID)
			}
			if gotEvent != test.wantEvent {
				t.Fatalf("event = %+v, want %+v", gotEvent, test.wantEvent)
			}
		})
	}
}

func TestHandleDeferredCredential(t *testing.T) {
	tests := []struct {
		name       string
		result     goidc.VCDeferralResult
		wantStatus int
	}{
		{
			name:       "pending",
			result:     goidc.VCDeferralResult{Pending: true},
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "resolved",
			result:     goidc.VCDeferralResult{Pending: false},
			wantStatus: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newDeferredContext(t, func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				return test.result, nil
			})
			ctx.VCISelfEnabled = true
			ctx.VCISelfCredentialEndpoint = "/credential"
			ctx.VCISelfDeferredCredentialEndpoint = "/deferred_credential"
			if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
				ID:                        "txn_id",
				GrantID:                   "grant",
				CredentialConfigurationID: "identity",
			}); err != nil {
				t.Fatalf("VCSaveDeferral() error = %v", err)
			}

			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			body, _ := json.Marshal(map[string]string{"transaction_id": "txn_id"})
			req := httptest.NewRequest(
				http.MethodPost,
				ctx.EndpointPrefix+ctx.VCISelfDeferredCredentialEndpoint,
				bytes.NewReader(body),
			)
			req.Header.Set("Authorization", "Bearer access_token")

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}

			var resp response
			if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if test.result.Pending {
				if resp.TransactionID != "txn_id" {
					t.Fatalf("transaction_id = %q, want %q", resp.TransactionID, "txn_id")
				}
			} else if len(resp.Credentials) != 1 {
				t.Fatalf("credentials = %+v, want one credential", resp.Credentials)
			}
		})
	}
}

func TestHandleJWTIssuerMetadata_URI(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		Host:                      "https://op.example.com",
		VCISelfEnabled:            true,
		VCISelfHost:               "https://credential-issuer.example.com",
		VCISelfCredentialEndpoint: "/credential",
		VCISelfJWTIssuerEnabled:   true,
		VCISelfJWTIssuerJWKSURI:   "https://credential-issuer.example.com/jwks",
		VCISelfJWTIssuerJWKSFunc:  nil,
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwt-vc-issuer", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var got jwtIssuerMetadata
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Issuer != "https://credential-issuer.example.com" {
		t.Fatalf("issuer = %q, want %q", got.Issuer, "https://credential-issuer.example.com")
	}
	if got.JWKSURI != "https://credential-issuer.example.com/jwks" {
		t.Fatalf("jwks_uri = %q, want %q", got.JWKSURI, "https://credential-issuer.example.com/jwks")
	}
	if got.JWKS != nil {
		t.Fatal("jwks must be empty when jwks_uri is set")
	}
}

func TestHandleJWTIssuerMetadata_InlineJWKS(t *testing.T) {
	jwk := oidctest.PrivateRS256JWK(t, "jwt_vc_issuer_key", goidc.KeyUsageSignature)
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		Host:                      "https://op.example.com",
		VCISelfEnabled:            true,
		VCISelfHost:               "https://credential-issuer.example.com",
		VCISelfCredentialEndpoint: "/credential",
		VCISelfJWTIssuerEnabled:   true,
		VCISelfJWTIssuerJWKSFunc: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwt-vc-issuer", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var got jwtIssuerMetadata
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.JWKSURI != "" {
		t.Fatalf("jwks_uri = %q, want empty", got.JWKSURI)
	}
	if got.JWKS == nil {
		t.Fatal("jwks must be set")
	}
	if len(got.JWKS.Keys) != 1 {
		t.Fatalf("jwks keys count = %d, want 1", len(got.JWKS.Keys))
	}
	if got.JWKS.Keys[0].KeyID != "jwt_vc_issuer_key" {
		t.Fatalf("jwk kid = %q, want %q", got.JWKS.Keys[0].KeyID, "jwt_vc_issuer_key")
	}
	if _, ok := got.JWKS.Keys[0].Key.(*rsa.PublicKey); !ok {
		t.Fatalf("jwk key type = %T, want *rsa.PublicKey", got.JWKS.Keys[0].Key)
	}
}
