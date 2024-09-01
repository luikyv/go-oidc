package authorize

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestInitAuth(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCodeAndIDToken,
			ResponseMode: goidc.ResponseModeFragment,
			Nonce:        "random_nonce",
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code in the session cannot be emtpy")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PolicyID:           ctx.Policies[0].ID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationCode:  session.AuthorizationCode,
		GrantedScopes:      client.ScopeIDs,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCodeAndIDToken,
			ResponseMode: goidc.ResponseModeFragment,
			Nonce:        "random_nonce",
		},
		AdditionalIDTokenClaims: map[string]any{
			"nonce": "random_nonce",
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}
	redirectParams, err := url.ParseQuery(redirectURL.Fragment)
	if err != nil {
		t.Fatalf("could not parse the redirect params: %v", err)
	}

	if redirectParams.Get("code") != session.AuthorizationCode {
		t.Errorf("the redirect url %s don't contain the code: %s", redirectURL, session.AuthorizationCode)
	}

	idToken := redirectParams.Get("id_token")
	if idToken == "" {
		t.Fatalf("the redirect url %s don't contain the id token", redirectURL)
	}

	claims, err := oidctest.SafeClaims(idToken, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":    ctx.Host,
		"sub":    session.Subject,
		"aud":    client.ID,
		"exp":    float64(now + ctx.IDTokenLifetimeSecs),
		"iat":    float64(now),
		"nonce":  "random_nonce",
		"c_hash": halfHash(session.AuthorizationCode),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestInitAuth_JAR(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	ctx.JARIsEnabled = true
	ctx.JARSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JARLifetimeSecs = 60

	privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	publicJWK := privateJWK.Public()
	client.PublicJWKS = oidctest.RawJWKS(publicJWK)

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      client.RedirectURIs[0],
		"scope":             client.ScopeIDs,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, _ := jwtutil.Sign(
		claims,
		privateJWK,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
			// These duplicated params are required for the openid profile.
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.ScopeIDs,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code in the session cannot be emtpy")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	if redirectURL.Query().Get("code") != session.AuthorizationCode {
		t.Errorf("the redirect url %s don't contain the code: %s", redirectURL, session.AuthorizationCode)
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PolicyID:           ctx.Policies[0].ID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationCode:  session.AuthorizationCode,
		GrantedScopes:      client.ScopeIDs,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}
}

func TestInitAuth_JARM(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	ctx.JARMIsEnabled = true
	ctx.JARMLifetimeSecs = 60
	ctx.JARMDefaultSigKeyID = ctx.PrivateJWKS.Keys[0].KeyID
	ctx.ResponseModes = append(ctx.ResponseModes, goidc.ResponseModeJWT)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeJWT,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code in the session cannot be emtpy")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	responseObject := redirectURL.Query().Get("response")
	if responseObject == "" {
		t.Fatalf("the redirect url %s don't contain the id token", responseObject)
	}

	claims, err := oidctest.SafeClaims(responseObject, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":  ctx.Host,
		"aud":  client.ID,
		"exp":  float64(now + ctx.JARMLifetimeSecs),
		"iat":  float64(now),
		"code": session.AuthorizationCode,
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestInitAuth_ShouldNotFindClient(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	req := request{ClientID: "invalid_client_id"}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("The client should not be found")
	}

	var oidcErr oidcerr.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != oidcerr.CodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, oidcerr.CodeInvalidClient)
	}
}

func TestInitAuth_InvalidRedirectURI(t *testing.T) {
	// Given
	ctx, client := setUpAuth(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI: "https://invalid.com",
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("the redirect uri should not be valid")
	}

	var oidcErr oidcerr.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != oidcerr.CodeInvalidRedirectURI {
		t.Errorf("error code = %s, want %s", oidcErr.Code, oidcerr.CodeInvalidRedirectURI)
	}
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       "invalid_scope",
			ResponseType: goidc.ResponseTypeCode,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("the error should be redirected")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	if redirectURL.Query().Get("error") != string(oidcerr.CodeInvalidScope) {
		t.Errorf("error code = %s, want %s", redirectURL.Query().Get("error"),
			oidcerr.CodeInvalidScope)
	}
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeIDToken,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("the error should be redirected")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	redirectParams, err := url.ParseQuery(redirectURL.Fragment)
	if err != nil {
		t.Fatalf("could not parse the redirect params: %v", err)
	}

	if redirectParams.Get("error") != string(oidcerr.CodeInvalidRequest) {
		t.Errorf("error code = %s, want %s", redirectParams.Get("error"),
			oidcerr.CodeInvalidScope)
	}
}

func TestInitAuth_NoPolicyAvailable(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	ctx.Policies = nil

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("the error should be redirected")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	if redirectURL.Query().Get("error") != string(oidcerr.CodeInvalidRequest) {
		t.Errorf("error code = %s, want %s", redirectURL.Query().Get("error"),
			oidcerr.CodeInvalidScope)
	}
}

func TestInitAuth_AuthnFailed(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusFailure
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("the error should be redirected")
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	if redirectURL.Query().Get("error") != string(oidcerr.CodeAccessDenied) {
		t.Errorf("error code = %s, want %s", redirectURL.Query().Get("error"),
			oidcerr.CodeAccessDenied)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("len(sessions) = %d, want 0", len(sessions))
	}
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	statusCode := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
	if statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.CallbackID == "" {
		t.Error("the callback id cannot be empty for an in progress authn")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PolicyID:           ctx.Policies[0].ID,
		CallbackID:         session.CallbackID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	}
	if diff := cmp.Diff(
		*session,
		wantedSession,
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}
}

func TestInitAuth_PAR(t *testing.T) {
	// Given.
	ctx, client := setUpAuth(t)
	ctx.PARIsEnabled = true

	requestURI := "urn:goidc:random_value"
	_ = ctx.SaveAuthnSession(
		&goidc.AuthnSession{
			ID: uuid.NewString(),
			AuthorizationParameters: goidc.AuthorizationParameters{
				RequestURI:   requestURI,
				Scopes:       client.ScopeIDs,
				RedirectURI:  client.RedirectURIs[0],
				ResponseType: goidc.ResponseTypeCode,
			},
			ClientID:           client.ID,
			ExpiresAtTimestamp: timeutil.TimestampNow() + 60,
		},
	)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:   requestURI,
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.ScopeIDs,
			State:        "random_state",
		},
	}

	// When.
	err := initAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be set in the session")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PolicyID:           ctx.Policies[0].ID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationCode:  session.AuthorizationCode,
		GrantedScopes:      client.ScopeIDs,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			State:        "random_state",
		},
	}
	if diff := cmp.Diff(
		*session,
		wantedSession,
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}

	redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("could not parse the redirect url: %v", err)
	}

	if redirectURL.Query().Get("code") != session.AuthorizationCode {
		t.Errorf("the redirect url %s don't contain the code: %s", redirectURL,
			session.AuthorizationCode)
	}
}

func TestContinueAuthentication(t *testing.T) {

	// Given.
	ctx, _ := setUpAuth(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	callbackID := "random_callback_id"
	_ = ctx.SaveAuthnSession(&goidc.AuthnSession{
		PolicyID:           policy.ID,
		CallbackID:         callbackID,
		ExpiresAtTimestamp: timeutil.TimestampNow() + 60,
	})

	// When.
	err := continueAuth(ctx, callbackID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusCode := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
	if statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Errorf("len(sessions) = %d, want 1", len(sessions))
	}
}

func setUpAuth(t *testing.T) (*oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up auth: %v", err)
	}

	policy := goidc.NewPolicy(
		"random_policy_id",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) goidc.AuthnStatus {
			as.GrantScopes(as.Scopes)
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	return ctx, client
}

func halfHash(claim string) string {
	hash := sha256.New()

	hash.Write([]byte(claim))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}
