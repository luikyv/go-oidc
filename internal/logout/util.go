package logout

import (
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initLogout(ctx oidc.Context, req request) error {
	if err := validateRequest(ctx, req); err != nil {
		return err
	}

	session, err := initLogoutSession(ctx, req)
	if err != nil {
		return err
	}

	if err := ctx.SaveLogoutSession(session); err != nil {
		return err
	}
	return logout(ctx, session)
}

func continueLogout(ctx oidc.Context, callbackID string) error {
	session, err := ctx.LogoutSessionByCallbackID(callbackID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	return logout(ctx, session)
}

func logout(ctx oidc.Context, session *goidc.LogoutSession) error {
	policy := ctx.LogoutPolicy(session.PolicyID)
	switch status, err := policy.Logout(ctx.Response, ctx.Request, session); status {
	case goidc.StatusSuccess:
		return finishLogoutSuccessfully(ctx, session)
	case goidc.StatusInProgress:
		return ctx.SaveLogoutSession(session)
	default:
		return finishLogoutWithFailure(ctx, session, err)
	}
}

func finishLogoutSuccessfully(ctx oidc.Context, session *goidc.LogoutSession) error {
	if err := ctx.DeleteLogoutSession(session.ID); err != nil {
		return err
	}

	redirectTo := ctx.DefaultLogoutRedirectURI(session)
	if session.PostLogoutRedirectURI != "" {
		redirectTo = session.PostLogoutRedirectURI
	}

	ctx.Redirect(redirectTo)
	return nil
}

func finishLogoutWithFailure(ctx oidc.Context, session *goidc.LogoutSession, err error) error {
	if err := ctx.DeleteLogoutSession(session.ID); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return goidc.NewError(goidc.ErrorCodeInternalError, "internal error")
}

func validateRequest(ctx oidc.Context, req request) error {

	if err := validatePostLogoutRedirectURI(ctx, req); err != nil {
		return err
	}

	if err := validateIDTokenHint(ctx, req); err != nil {
		return err
	}

	return nil
}

func validatePostLogoutRedirectURI(ctx oidc.Context, req request) error {
	if req.PostLogoutRedirectURI == "" {
		return nil
	}

	if req.ClientID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_id is required when post_logout_redirect_uri is provided")
	}

	c, err := ctx.Client(req.ClientID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid client_id", err)
	}

	if !slices.Contains(c.PostLogoutRedirectURIs, req.PostLogoutRedirectURI) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "post_logout_redirect_uri not allowed for the client")
	}

	return nil
}

func validateIDTokenHint(ctx oidc.Context, req request) error {

	if req.IDTokenHint == "" {
		return nil
	}

	parsedIDToken, err := jwt.ParseSigned(req.IDTokenHint, ctx.IDTokenSigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	if len(parsedIDToken.Headers) != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid id token hint")
	}

	publicKey, err := ctx.PublicJWK(parsedIDToken.Headers[0].KeyID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	var claims jwt.Claims
	if err := parsedIDToken.Claims(publicKey.Key, &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	var aud []string
	if req.ClientID != "" {
		aud = append(aud, req.ClientID)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      ctx.Issuer(),
		AnyAudience: aud,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	return nil
}

func initLogoutSession(ctx oidc.Context, req request) (*goidc.LogoutSession, error) {
	session := &goidc.LogoutSession{
		ID:                 uuid.NewString(),
		ClientID:           req.ClientID,
		CallbackID:         callbackID(),
		ExpiresAtTimestamp: timeutil.TimestampNow() + ctx.LogoutSessionTimeoutSecs,
		CreatedAtTimestamp: timeutil.TimestampNow(),
		LogoutParameters:   req.LogoutParameters,
	}

	policy, ok := ctx.AvailableLogoutPolicy(session)
	if !ok {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "no logout policy available")
	}
	session.PolicyID = policy.ID

	if session.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(session.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&session.IDTokenHintClaims)
	}
	return session, nil

}

func callbackID() string {
	return strutil.Random(callbackIDLength)
}
