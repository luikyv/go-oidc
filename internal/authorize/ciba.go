package authorize

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// initBackAuth inits an authentication session for CIBA.
func initBackAuth(ctx oidc.Context, req request) (cibaResponse, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return cibaResponse{}, err
	}

	as, err := func() (*goidc.AuthnSession, error) {
		jar := ctx.CIBAJARIsEnabled && (ctx.CIBAJARIsRequired || c.CIBAJARSigAlg != "" || req.RequestObject != "")
		if jar {
			if req.RequestObject == "" {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request object is required"))
			}

			algs := ctx.CIBAJARSigAlgs
			if c.CIBAJARSigAlg != "" {
				algs = []goidc.SignatureAlgorithm{c.CIBAJARSigAlg}
			}

			parsedToken, err := jwt.ParseSigned(req.RequestObject, algs)
			if err != nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", fmt.Errorf("could not parse request object: %w", err))
			}

			// Verify that the assertion indicates the key ID.
			if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("kid header is required in the request object"))
			}

			// Verify that the key ID belongs to the client.
			jwk, err := client.JWKByKeyID(ctx, c, parsedToken.Headers[0].KeyID)
			if err != nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", fmt.Errorf("could not resolve the client public key for kid %q: %w", parsedToken.Headers[0].KeyID, err))
			}

			var claims jwt.Claims
			var requestObject request
			if err := parsedToken.Claims(jwk.Key, &claims, &requestObject); err != nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", fmt.Errorf("could not extract claims from the request object: %w", err))
			}

			if claims.IssuedAt == nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'iat' is required in the request object"))
			}

			if claims.NotBefore == nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'nbf' is required in the request object"))
			}

			if claims.NotBefore.Time().Before(timeutil.Now().Add(-1 * time.Hour)) {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'nbf' is too far in the past"))
			}

			if claims.Expiry == nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'exp' is required in the request object"))
			}

			if claims.Expiry.Time().After(timeutil.Now().Add(1 * time.Hour)) {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'exp' is too far in the future"))
			}

			if claims.ID == "" {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", errors.New("claim 'jti' is required in the request object"))
			}

			if err := ctx.ConsumeJTI(claims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", fmt.Errorf("could not validate the request object jti: %w", err))
			}

			if err := claims.ValidateWithLeeway(jwt.Expected{
				Issuer:      c.ID,
				AnyAudience: []string{ctx.Issuer()},
			}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", fmt.Errorf("the request object contains invalid claims: %w", err))
			}

			if err := validateCIBARequest(ctx, requestObject, c); err != nil {
				return nil, err
			}

			return newAuthnSession(ctx, requestObject.AuthorizationParameters, c), nil
		}

		if err := validateCIBARequest(ctx, req, c); err != nil {
			return nil, err
		}
		return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
	}()
	if err != nil {
		return cibaResponse{}, err
	}

	exp := ctx.CIBADefaultSessionLifetimeSecs
	if as.RequestedExpiry != nil {
		exp = *as.RequestedExpiry
	}
	as.AuthReqID = ctx.CIBAID()
	as.ExpiresAt = timeutil.TimestampNow() + exp
	if as.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(as.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&as.IDTokenHintClaims)
	}

	// Store binding information only for CIBA push mode.
	// For other modes, binding occurs at the token endpoint.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
		if ctx.DPoPIsEnabled {
			if dpopJWT, ok := dpop.JWT(ctx); ok {
				as.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
			}
		}
		if ctx.MTLSTokenBindingIsEnabled {
			if cert, err := ctx.ClientCert(); err == nil {
				as.ClientCertThumbprint = hashutil.Thumbprint(string(cert.Raw))
			}
		}
	}

	if err := ctx.CIBAHandleSession(as, c); err != nil {
		return cibaResponse{}, fmt.Errorf("could not handle the pending CIBA session: %w", err)
	}

	if err := ctx.CIBASaveSession(as); err != nil {
		return cibaResponse{}, fmt.Errorf("could not save the pending CIBA session: %w", err)
	}

	resp := cibaResponse{
		AuthReqID: as.AuthReqID,
		ExpiresIn: as.ExpiresAt - timeutil.TimestampNow(),
	}

	if c.CIBATokenDeliveryMode.IsPollableMode() {
		resp.Interval = ctx.CIBAPollingIntervalSecs
	}

	return resp, nil
}

func validateCIBARequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the CIBA grant type"))
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(req.Scopes) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "scope openid is required", errors.New("scope openid is required"))
	}

	if req.ClientNotificationToken == "" && c.CIBATokenDeliveryMode.IsNotificationMode() {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("client_notification_token is required for ping and push delivery modes"))
	}

	if len(req.ClientNotificationToken) > 1024 {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("client_notification_token length %d exceeds the maximum allowed length", len(req.ClientNotificationToken)))
	}

	if req.UserCode != "" && (!ctx.CIBAUserCodeIsEnabled || !c.CIBAUserCodeIsEnabled) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("user_code is not allowed for this client or server configuration"))
	}

	if err := validateCIBAHints(ctx, req, c); err != nil {
		return err
	}

	if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, c); err != nil {
		return err
	}

	// Validate token binding rules only for CIBA push mode.
	// For other modes, token binding occurs at the token endpoint.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
		if err := token.ValidateBinding(ctx, c, nil); err != nil {
			return err
		}
	}

	return nil
}

func validateCIBAHints(_ oidc.Context, req request, _ *goidc.Client) error {
	numberOfHints := 0

	if req.LoginHint != "" {
		numberOfHints++
	}

	if req.LoginHintToken != "" {
		numberOfHints++
	}

	if req.IDTokenHint != "" {
		numberOfHints++
	}

	if numberOfHints != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("exactly one of login_hint, login_hint_token, or id_token_hint must be provided"))
	}

	return nil
}
