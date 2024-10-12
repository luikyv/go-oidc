package clientutil_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticated_ClientNotFound(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnNone,
		},
	}
	ctx.Request.PostForm = map[string][]string{"client_id": {c.ID}}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be found")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_NoneAuthn(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnNone,
		},
	}
	ctx.Request.PostForm = map[string][]string{"client_id": {c.ID}}
	_ = ctx.SaveClient(c)

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

func TestAuthenticated_SecretPostAuthn(t *testing.T) {

	// Given.
	ctx, client, secret := setUpSecretAuthn(t, goidc.ClientAuthnSecretPost)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

func TestAuthenticated_SecretPostAuthn_InvalidSecret(t *testing.T) {

	// Given.
	ctx, client, _ := setUpSecretAuthn(t, goidc.ClientAuthnSecretPost)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_SecretPostAuthn_MissingSecret(t *testing.T) {

	// Given.
	ctx, client, _ := setUpSecretAuthn(t, goidc.ClientAuthnSecretPost)
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

// TestAuthenticated_SecretPostAuthn_InvalidID tests that the form parameter
// "client_id" is equal to the ID of the authenticated client.
func TestAuthenticated_SecretPostAuthn_InvalidID(t *testing.T) {

	// Given.
	ctx, client, secret := setUpSecretAuthn(t, goidc.ClientAuthnSecretPost)
	// The client ID is supposed to be the value of the param "client_id", but
	// will be sent in the authorization header.
	ctx.Request.SetBasicAuth(client.ID, secret)
	ctx.Request.PostForm = map[string][]string{
		"client_secret": {"invalid_secret"},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_BasicSecretAuthn(t *testing.T) {

	// Given.
	ctx, client, secret := setUpSecretAuthn(t, goidc.ClientAuthnSecretBasic)
	ctx.Request.SetBasicAuth(client.ID, secret)

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

func TestAuthenticated_BasicSecretAuthn_InvalidSecret(t *testing.T) {

	// Given.
	ctx, client, _ := setUpSecretAuthn(t, goidc.ClientAuthnSecretBasic)
	ctx.Request.SetBasicAuth(client.ID, "invalid_secret")

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_BasicSecretAuthn_MissingSecret(t *testing.T) {

	// Given.
	ctx, client, _ := setUpSecretAuthn(t, goidc.ClientAuthnSecretBasic)
	// Add the client ID to the request so it can be identified.
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_PrivateKeyJWT(t *testing.T) {

	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
		goidc.ClaimTokenID:  "random_jti",
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

// TestAuthenticated_PrivateKeyJWT_ClientInformedSigningAlgorithms tests that a
// client can sign an assertion with its authentication algorithm.
func TestAuthenticated_PrivateKeyJWT_ClientInformedSigningAlgorithms(t *testing.T) {

	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	client.TokenAuthnSigAlg = jose.SignatureAlgorithm(jwk.Algorithm)
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
		goidc.ClaimTokenID:  "random_jti",
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

// TestAuthenticated_PrivateKeyJWT_ClientInformedSigningAlgorithms_InvalidSignature
// tests that an assertion signed with an algorithm different from the client's
// authentication algorithm will result in failure.
func TestAuthenticated_PrivateKeyJWT_ClientInformedSigningAlgorithms_InvalidSignature(t *testing.T) {

	// Given the client must sign assertions with PS256 and the signing JWK uses
	// RS256.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	client.TokenAuthnSigAlg = jose.PS256
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_PrivateKeyJWT_InvalidAudienceClaim(t *testing.T) {
	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	// The "aud" claim is not included in the claims.
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_PrivateKeyJWT_InvalidExpiryClaim(t *testing.T) {
	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	// The "exp" claim is not included in the claims.
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

// TestAuthenticated_PrivateKeyJWT_CannotIdentifyJWK tests that an assertion
// signed with a key that doesn't belong to the client results in error.
func TestAuthenticated_PrivateKeyJWT_CannotIdentifyJWK(t *testing.T) {
	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	client.PublicJWKS = nil
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

// TestAuthenticated_PrivateKeyJWT_InvalidSigningKey tests that an assertion
// signed with an unauthorized key that has the same ID of one of the client's
// keys results in error.
func TestAuthenticated_PrivateKeyJWT_InvalidSigningKey(t *testing.T) {
	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
	}

	invalidJWK := oidctest.PrivateRS256JWK(t, jwk.KeyID, goidc.KeyUsageSignature)
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {
			signAssertion(t, claims, invalidJWK),
		},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

// TestAuthenticated_PrivateKeyJWT_InvalidAssertion tests that a client
// assertion which is not a JWT will result in error.
func TestAuthenticated_PrivateKeyJWT_InvalidAssertion(t *testing.T) {
	// Given.
	ctx, client, _ := setUpPrivateKeyJWTAuthn(t)
	ctx.Request.PostForm = map[string][]string{
		// Add the ID so the client can be identified.
		"client_id":             {client.ID},
		"client_assertion":      {"invalid_assertion"},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_PrivateKeyJWT_InvalidAssertionType(t *testing.T) {
	// Given.
	ctx, client, jwk := setUpPrivateKeyJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
	}

	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {signAssertion(t, claims, jwk)},
		"client_assertion_type": {"invalid_assertion_type"},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_ClientSecretJWT(t *testing.T) {

	// Given.
	ctx, client, secret := setUpClientSecretJWTAuthn(t)
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.AssertionLifetimeSecs - 10,
		goidc.ClaimTokenID:  "random_jti",
	}
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)},
		(&jose.SignerOptions{}).WithType("jwt"),
	)
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}

}

// TestAuthenticated_DifferentClientIDs tests that when different client IDs are
// sent in the request, the client won't be authenticated.
// For instance, the form parameter "client_id" could have value "client_one"
// and the issuer of the parameter "client_assertion" could have value
// "client_two". In that case, the client must not be authenticate.
func TestAuthenticated_DifferentClientIDs(t *testing.T) {

	// When.
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnNone,
		},
	}

	ctx := oidctest.NewContext(t)
	_ = ctx.SaveClient(c)
	ctx.PrivateKeyJWTSigAlgs = []jose.SignatureAlgorithm{jose.PS256}

	ctx.Request.PostForm = map[string][]string{
		"client_id": {c.ID},
		// The issuer claim should be the client ID, so this assertion has issuer as "invalid_client_id",
		// so the unhappy path can be tested.
		"client_assertion":      {"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbnZhbGlkX2NsaWVudF9pZCIsInN1YiI6ImludmFsaWRfY2xpZW50X2lkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Nog3Y_jeWO0dugsTKCxLx_vGcCbE6kRHzo7wAvfnKe7_uCW9UB1f-WhX4fMKXvJ8v-bScuyx2pTgy4C6ie0ZAcOn_XESblpr_0epoUF2ibdR5DGPKcrPs-S8jp8yvBOxbUmq0jyU9V5H33052h5gBsEAcYXnM150S-ch_1ISL1EgDiZrOm9lYhisp7Jp_mqUZx3OXjfWruz4d6oLe5FeCg7NsB5PpT_N26VZ6Qxt9x6OKUvphRHN1niETkf3_1uTr8CltHesfFl4NnaXSP5f7QStg9JKIpjgJnl-LeQe2C4tM8yHCTENxgHX4oTzrfiEfdN3TwoHDFNszcXnnAUQCg"},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_TLSAuthn_DistinguishedName(t *testing.T) {

	// Given.
	ctx, client := setUpTLSAuthn(t)
	client.TLSSubDistinguishedName = "CN=https://example.com"
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

func TestAuthenticated_TLSAuthn_InvalidDistinguishedName(t *testing.T) {

	// Given.
	ctx, client := setUpTLSAuthn(t)
	client.TLSSubDistinguishedName = "invalid"
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestAuthenticated_TLSAuthn_AlternativeName(t *testing.T) {

	// Given.
	ctx, client := setUpTLSAuthn(t)
	client.TLSSubAlternativeName = "https://sub.example.com"
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
}

func TestAuthenticated_TLSAuthn_InvalidAlternativeName(t *testing.T) {

	// Given.
	ctx, client := setUpTLSAuthn(t)
	client.TLSSubAlternativeName = "invalid"
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	// When.
	_, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func setUpSecretAuthn(t *testing.T, secretAuthnMethod goidc.ClientAuthnType) (
	ctx oidc.Context,
	client *goidc.Client,
	secret string,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	secret = "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), 0)
	client = &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: secretAuthnMethod,
		},
		HashedSecret: string(hashedClientSecret),
	}
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up secret authn: %v", err)
	}

	return ctx, client, secret
}

func setUpPrivateKeyJWTAuthn(t *testing.T) (
	ctx oidc.Context,
	client *goidc.Client,
	jwk jose.JSONWebKey,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.PrivateKeyJWTSigAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.AssertionLifetimeSecs = 60

	jwk = oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	client = &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:       oidctest.RawJWKS(jwk.Public()),
		},
	}
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up private key jwt authn: %v", err)
	}

	return ctx, client, jwk
}

func setUpClientSecretJWTAuthn(t *testing.T) (
	ctx oidc.Context,
	client *goidc.Client,
	secret string,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.ClientSecretJWTSigAlgs = []jose.SignatureAlgorithm{jose.HS256}
	ctx.AssertionLifetimeSecs = 60

	secret = "random_password12345678910111213"
	client = &goidc.Client{
		ID:     "random_client_id",
		Secret: secret,
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnSecretJWT,
		},
	}
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up secret jwt authn: %v", err)
	}

	return ctx, client, secret
}

func signAssertion(t *testing.T, claims map[string]any, jwk jose.JSONWebKey) string {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID)
	assertion, err := jwtutil.Sign(claims, jwk, opts)
	if err != nil {
		t.Fatalf("could not sign the claims: %v", err)
	}

	return assertion
}

func setUpTLSAuthn(t *testing.T) (
	ctx oidc.Context,
	client *goidc.Client,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.ClientCertFunc = func(r *http.Request) (*x509.Certificate, error) {
		return &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "https://example.com",
			},
			DNSNames: []string{"https://sub.example.com"},
		}, nil
	}

	client = &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnTLS,
		},
	}
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up tls authn: %v", err)
	}

	return ctx, client
}
