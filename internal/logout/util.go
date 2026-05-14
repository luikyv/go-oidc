package logout

import (
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initLogout(ctx oidc.Context, req request) error {
	c, err := func() (*goidc.Client, error) {
		if req.ClientID != "" {
			return client.Client(ctx, req.ClientID)
		}

		if req.IDTokenHint != "" {
			idToken, err := jwt.ParseSigned(req.IDTokenHint, ctx.IDTokenSigAlgs)
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

			return client.Client(ctx, claims.ClientID)
		}

		return &goidc.Client{}, nil
	}()
	if err != nil {
		return err
	}

	if err := validateRequest(ctx, req, c); err != nil {
		return err
	}

	ls := &goidc.LogoutSession{
		ID:               ctx.LogoutSessionID(),
		Status:           goidc.StatusInProgress,
		ClientID:         c.ID,
		ExpiresAt:        timeutil.TimestampNow() + ctx.LogoutSessionTimeoutSecs,
		CreatedAt:        timeutil.TimestampNow(),
		LogoutParameters: req.LogoutParameters,
	}

	policy, ok := ctx.AvailableLogoutPolicy(ls)
	if !ok {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "no logout policy available")
	}

	ls.PolicyID = policy.ID
	if ls.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(ls.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&ls.IDTokenHintClaims)
	}

	if err := ctx.SaveLogoutSession(ls); err != nil {
		return err
	}
	return logout(ctx, ls)
}

func continueLogout(ctx oidc.Context, id string) error {
	session, err := ctx.LogoutSession(id)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	return logout(ctx, session)
}

func logout(ctx oidc.Context, ls *goidc.LogoutSession) error {
	if ls.PolicyID == "" {
		if err := ctx.DeleteLogoutSession(ls.ID); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", err)
		}
		return goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", errors.New("the policy id is not set in the session"))
	}

	policy := ctx.LogoutPolicy(ls.PolicyID)
	switch status, err := policy.Logout(ctx.Response, ctx.Request, ls); status {
	case goidc.StatusSuccess:
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

		return ctx.HandleDefaultPostLogout(ls)
	case goidc.StatusInProgress:
		return ctx.SaveLogoutSession(ls)
	default:
		if deleteErr := ctx.DeleteLogoutSession(ls.ID); deleteErr != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "failed to logout", deleteErr)
		}

		if err != nil {
			return err
		}
		return goidc.NewError(goidc.ErrorCodeInternalError, "failed to logout")
	}
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
