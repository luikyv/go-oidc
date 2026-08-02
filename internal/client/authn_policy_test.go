package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestPrivateKeyJWTAssertionPolicyRunsBeforeJTIConsumption(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	ctx.JWTLeewayTimeSecs = 7
	now := timeutil.TimestampNow()
	expiresAt := now + ctx.JWTLifetimeSecs - 10
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   expiresAt,
		goidc.ClaimTokenID:  "assertion-id",
		"custom":            "value",
	}
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {
			oidctest.SignWithOptions(t, claims, jwk, (&jose.SignerOptions{}).WithType("JWT")),
		},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	var calls []string
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, assertion goidc.VerifiedClientAssertion) error {
		calls = append(calls, "policy")
		if assertion.Header.Algorithm != goidc.SigAlgRS256 {
			t.Errorf("policy header algorithm = %q, want %q", assertion.Header.Algorithm, goidc.SigAlgRS256)
		}
		if assertion.Header.KeyID != jwk.KeyID {
			t.Errorf("policy header kid = %q, want %q", assertion.Header.KeyID, jwk.KeyID)
		}
		if assertion.Header.Type != "JWT" {
			t.Errorf("policy header typ = %q, want JWT", assertion.Header.Type)
		}
		var gotClaims map[string]json.RawMessage
		if err := json.Unmarshal(assertion.Claims, &gotClaims); err != nil {
			t.Fatalf("unmarshal verified claims: %v", err)
		}
		if string(gotClaims["custom"]) != `"value"` {
			t.Errorf("policy custom claim = %s, want %q", gotClaims["custom"], "value")
		}
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		calls = append(calls, "consume")
		if use.ID != "assertion-id" {
			t.Errorf("JTI ID = %q, want assertion-id", use.ID)
		}
		if use.Issuer != c.ID {
			t.Errorf("JTI issuer = %q, want %q", use.Issuer, c.ID)
		}
		if use.Purpose != goidc.JTIUsePurposeClientAssertion {
			t.Errorf("JTI purpose = %q, want %q", use.Purpose, goidc.JTIUsePurposeClientAssertion)
		}
		wantExpiry := time.Unix(int64(expiresAt+ctx.JWTLeewayTimeSecs), 0).UTC()
		if !use.ExpiresAt.Equal(wantExpiry) {
			t.Errorf("JTI expiry = %v, want %v", use.ExpiresAt, wantExpiry)
		}
		return nil
	}

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	if want := []string{"policy", "consume"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestPrivateKeyJWTAssertionPolicyRejectsBeforeJTIConsumption(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		return errors.New("assertion violates deployment policy")
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called after assertion policy rejection")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAssertionPolicyPreservesOperationalFailure(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "internal server error", errors.New("policy store unavailable"))
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInternalError)
}

func TestTypedJTIConsumerDistinguishesReplayFromOperationalFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		consume  error
		wantCode goidc.ErrorCode
	}{
		{name: "replay", consume: goidc.ErrJTIReplay, wantCode: goidc.ErrorCodeInvalidClient},
		{name: "operational failure", consume: errors.New("store unavailable"), wantCode: goidc.ErrorCodeInternalError},
		{name: "not found is operational", consume: goidc.ErrNotFound, wantCode: goidc.ErrorCodeInternalError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			now := timeutil.TimestampNow()
			ctx.Request.PostForm = map[string][]string{
				"client_assertion": {oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "assertion-id",
				}, jwk)},
				"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error { return tc.consume }

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, tc.wantCode)
		})
	}
}

func TestInvalidPrivateKeyJWTClaimsAreNotConsumed(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: "https://wrong.example",
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called before claims validation")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestSecretJWTConsumesTypedJTI(t *testing.T) {
	ctx, c, secret := setUpClientSecretJWTAuthn(t)
	ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "secret-assertion-id")
	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	if got.ID != "secret-assertion-id" {
		t.Errorf("JTI ID = %q, want secret-assertion-id", got.ID)
	}
	if got.Issuer != c.ID {
		t.Errorf("JTI issuer = %q, want %q", got.Issuer, c.ID)
	}
	if got.Purpose != goidc.JTIUsePurposeClientAssertion {
		t.Errorf("JTI purpose = %q, want %q", got.Purpose, goidc.JTIUsePurposeClientAssertion)
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Errorf("JTI expiry = %v, want a future time", got.ExpiresAt)
	}
}

func TestAttestationPoPConsumesTypedJTI(t *testing.T) {
	ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
	cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.SigAlgES256)}
	clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.SigAlgES256)}
	attestation := oidctest.SignWithOptions(t, map[string]any{
		goidc.ClaimIssuer:  "https://attester.example.com",
		goidc.ClaimSubject: c.ID,
		goidc.ClaimExpiry:  timeutil.TimestampNow() + 300,
		"cnf":              map[string]any{"jwk": cnfJWK},
	}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
	ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

	expiresAt := timeutil.TimestampNow() + 60
	pop := oidctest.SignWithOptions(t, map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimExpiry:   expiresAt,
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimTokenID:  "attestation-pop-id",
	}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
	ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)

	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}
	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	wantExpiry := time.Unix(int64(expiresAt+ctx.JWTLeewayTimeSecs), 0).UTC()
	if got.ID != "attestation-pop-id" || got.Issuer != c.ID || got.Purpose != goidc.JTIUsePurposeClientAttestationPoP {
		t.Fatalf("JTI use = %#v, want attestation PoP reservation", got)
	}
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("JTI expiry = %v, want %v", got.ExpiresAt, wantExpiry)
	}
}

func assertErrorCode(t *testing.T, err error, want goidc.ErrorCode) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error", err)
	}
	if oidcErr.Code != want {
		t.Fatalf("error code = %q, want %q (error: %v)", oidcErr.Code, want, err)
	}
	if oidcErr.StatusCode() != want.StatusCode() {
		t.Fatalf("HTTP status = %d, want %d", oidcErr.StatusCode(), want.StatusCode())
	}
}
