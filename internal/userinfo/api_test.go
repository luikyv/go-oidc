package userinfo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestUserInfoEndpointDPoPNonce(t *testing.T) {
	tests := []struct {
		name       string
		nonce      string
		rotateTo   string
		wantStatus int
		wantNonce  string
		wantError  goidc.ErrorCode
	}{
		{
			name:       "challenge",
			wantStatus: http.StatusUnauthorized,
			wantNonce:  "challenge_nonce",
			wantError:  goidc.ErrorCodeUseDPoPNonce,
		},
		{
			name:       "success with reusable nonce",
			nonce:      "current_nonce",
			wantStatus: http.StatusOK,
		},
		{
			name:       "success rotates nonce when requested",
			nonce:      "current_nonce",
			rotateTo:   "next_nonce",
			wantStatus: http.StatusOK,
			wantNonce:  "next_nonce",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.DPoPEnabled = true
			ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
			manager := oidctest.NewDPoPNonceManager(test.wantNonce)
			ctx.DPoPNonceManager = manager
			if test.nonce != "" {
				manager.Add(goidc.DPoPNonceScopeResourceServer, test.nonce)
			}
			if test.rotateTo != "" {
				manager.RotateWith(test.rotateTo)
			}

			client, _ := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			grant := &goidc.Grant{
				ID:        "grant_id",
				ClientID:  client.ID,
				Subject:   "subject",
				CreatedAt: timeutil.TimestampNow(),
			}
			if err := ctx.SaveGrant(grant); err != nil {
				t.Fatalf("SaveGrant() error = %v", err)
			}
			ctx.UserInfoClaimsFunc = func(context.Context, *goidc.Grant) map[string]any { return nil }

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			_, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodGet,
				URI:    ctx.Host + ctx.UserInfoEndpoint,
				Key:    key,
			})
			now := timeutil.TimestampNow()
			accessToken := oidctest.Sign(t, map[string]any{
				"jti":       "token_id",
				"grant_id":  grant.ID,
				"iss":       ctx.Issuer(),
				"sub":       grant.Subject,
				"client_id": client.ID,
				"scope":     goidc.ScopeOpenID.ID,
				"iat":       now,
				"exp":       now + 60,
				"cnf":       map[string]any{"jkt": thumbprint},
			}, oidctest.PrivateJWKS(t, ctx).Keys[0])
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method:      http.MethodGet,
				URI:         ctx.Host + ctx.UserInfoEndpoint,
				AccessToken: accessToken,
				Nonce:       test.nonce,
				Key:         key,
			})

			req := httptest.NewRequest(http.MethodGet, ctx.UserInfoEndpoint, nil)
			req.Header.Set("Authorization", fmt.Sprintf("DPoP %s", accessToken))
			req.Header.Set(goidc.HeaderDPoP, proof)
			rec := httptest.NewRecorder()
			handle(oidc.NewHTTPContext(rec, req, ctx.Configuration))

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, test.wantStatus, rec.Body.String())
			}
			gotNonces := rec.Header().Values(goidc.HeaderDPoPNonce)
			if test.wantNonce == "" && len(gotNonces) != 0 {
				t.Fatalf("%s = %v, want empty", goidc.HeaderDPoPNonce, gotNonces)
			}
			if test.wantNonce != "" && (len(gotNonces) != 1 || gotNonces[0] != test.wantNonce) {
				t.Fatalf("%s = %v, want [%s]", goidc.HeaderDPoPNonce, gotNonces, test.wantNonce)
			}
			if test.wantError != "" {
				if !strings.Contains(rec.Body.String(), `"error":"`+string(test.wantError)+`"`) {
					t.Fatalf("body = %s, want error %q", rec.Body.String(), test.wantError)
				}
				if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `DPoP error="use_dpop_nonce"`) {
					t.Fatalf("WWW-Authenticate = %q, want DPoP nonce challenge", got)
				}
			} else if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q, want empty", got)
			}
		})
	}
}
