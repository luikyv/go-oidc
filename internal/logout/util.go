package logout

import (
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initLogout(ctx oidc.Context, req request) error {
	c, err := fetchClient(ctx, req)
	if err != nil {
		return err
	}

	if err := validateRequest(ctx, req, c); err != nil {
		return err
	}

	session, err := initLogoutSession(ctx, req, c)
	if err != nil {
		return err
	}

	if err := ctx.SaveLogoutSession(session); err != nil {
		return err
	}
	return logout(ctx, session)
}

// fetchClient retrieves the client based on the request parameters.
// If the client cannot be determined, it returns an empty client.
func fetchClient(ctx oidc.Context, req request) (*goidc.Client, error) {
	if req.ClientID != "" {
		return ctx.Client(req.ClientID)
	}

	if req.IDTokenHint != "" {
		return fetchClientFromIDTokenHint(ctx, req.IDTokenHint)
	}

	return &goidc.Client{}, nil
}

// fetchClientFromIDTokenHint retrieves the client based on the provided ID token hint.
// If the client cannot be determined, it returns an empty client.
func fetchClientFromIDTokenHint(ctx oidc.Context, idTokenHint string) (*goidc.Client, error) {
	idToken, err := jwt.ParseSigned(idTokenHint, ctx.IDTokenSigAlgs)
	if err != nil {
		return &goidc.Client{}, nil
	}

	var claims struct {
		ClientID string `json:"aud"`
	}
	_ = idToken.UnsafeClaimsWithoutVerification(&claims)
	if claims.ClientID == "" {
		return &goidc.Client{}, nil
	}

	return ctx.Client(claims.ClientID)
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

func finishLogoutSuccessfully(ctx oidc.Context, ls *goidc.LogoutSession) error {
	if err := ctx.DeleteLogoutSession(ls.ID); err != nil {
		return err
	}

	if ls.PostLogoutRedirectURI != "" {
		params := make(map[string]string)
		if ls.State != "" {
			params["state"] = ls.State
		}
		ctx.Redirect(strutil.URLWithQueryParams(ls.PostLogoutRedirectURI, params))
		return nil
	}

	if err := ctx.HandleDefaultPostLogout(ls); err != nil {
		return ctx.RenderError(err)
	}

	return nil
}

func finishLogoutWithFailure(ctx oidc.Context, session *goidc.LogoutSession, err error) error {
	if deleteErr := ctx.DeleteLogoutSession(session.ID); deleteErr != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "failed to logout", deleteErr)
	}

	if err != nil {
		return err
	}

	return goidc.NewError(goidc.ErrorCodeInternalError, "failed to logout")
}

func validateRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if err := validateIDTokenHint(ctx, req, c); err != nil {
		return err
	}

	return validatePostLogoutRedirectURI(ctx, req, c)
}

func validatePostLogoutRedirectURI(_ oidc.Context, req request, c *goidc.Client) error {
	if req.PostLogoutRedirectURI == "" {
		return nil
	}

	if !slices.Contains(c.PostLogoutRedirectURIs, req.PostLogoutRedirectURI) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "post_logout_redirect_uri not allowed")
	}

	return nil
}

func validateIDTokenHint(ctx oidc.Context, req request, _ *goidc.Client) error {

	if req.IDTokenHint == "" {
		return nil
	}

	if !joseutil.IsJWS(req.IDTokenHint) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid id token hint")
	}

	// TODO: What if the id token is signed with "none" alg? joseutil.IsUnsignedJWT
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

func initLogoutSession(ctx oidc.Context, req request, c *goidc.Client) (*goidc.LogoutSession, error) {
	session := &goidc.LogoutSession{
		ID:                 uuid.NewString(),
		ClientID:           c.ID,
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
