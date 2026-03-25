package authorize

import (
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
				return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request object is required")
			}

			jar, err := cibaJARFromRequestObject(ctx, req.RequestObject, c)
			if err != nil {
				return nil, err
			}

			if err := validateCIBARequest(ctx, jar, c); err != nil {
				return nil, err
			}

			return newAuthnSession(ctx, jar.AuthorizationParameters, c), nil
		}

		if err := validateCIBARequest(ctx, req, c); err != nil {
			return nil, err
		}
		return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
	}()
	if err != nil {
		return cibaResponse{}, err
	}

	as.CIBAAuthID = ctx.CIBAAuthReqID()
	exp := ctx.CIBADefaultSessionLifetimeSecs
	if as.RequestedExpiry != nil {
		exp = *as.RequestedExpiry
	}
	as.ExpiresAtTimestamp = timeutil.TimestampNow() + exp
	if as.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(as.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&as.IDTokenHintClaims)
	}

	// Store binding information only for CIBA push mode.
	// For other modes, binding occurs at the token endpoint.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
		if dpopJWT, ok := dpop.JWT(ctx); ctx.DPoPIsEnabled && ok {
			as.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
		}

		if cert, err := ctx.ClientCert(); ctx.MTLSTokenBindingIsEnabled && err == nil {
			as.ClientCertThumbprint = hashutil.Thumbprint(string(cert.Raw))
		}
	}

	if err := ctx.CIBAHandleSession(as, c); err != nil {
		return cibaResponse{}, err
	}

	if err := ctx.SaveAuthnSession(as); err != nil {
		return cibaResponse{}, err
	}

	resp := cibaResponse{
		AuthReqID: as.CIBAAuthID,
		ExpiresIn: as.ExpiresAtTimestamp - timeutil.TimestampNow(),
	}

	if c.CIBATokenDeliveryMode.IsPollableMode() {
		resp.Interval = ctx.CIBAPollingIntervalSecs
	}

	return resp, nil
}

func cibaJARFromRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
	algs := ctx.CIBAJARSigAlgs
	if c.CIBAJARSigAlg != "" {
		algs = []goidc.SignatureAlgorithm{c.CIBAJARSigAlg}
	}

	parsedToken, err := jwt.ParseSigned(reqObject, algs)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", err)
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := client.JWKByKeyID(ctx, c, parsedToken.Headers[0].KeyID)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch the client public key", err)
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not extract claims from the request object", err)
	}

	if err := validateCIBAJARClaims(ctx, claims, c); err != nil {
		return request{}, err
	}

	return jarReq, nil
}

func validateCIBAJARClaims(ctx oidc.Context, claims jwt.Claims, c *goidc.Client) error {
	if claims.IssuedAt == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'iat' is required in the request object")
	}

	if claims.NotBefore == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'nbf' is required in the request object")
	}

	if claims.NotBefore.Time().Before(timeutil.Now().Add(-1 * time.Hour)) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'nbf' is too far in the past")
	}

	if claims.Expiry == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'exp' is required in the request object")
	}

	if claims.Expiry.Time().After(timeutil.Now().Add(1 * time.Hour)) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'exp' is too far in the future")
	}

	if claims.ID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "claim 'jti' is required in the request object")
	}

	if err := ctx.CheckJTI(claims.ID); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid jti claim", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Issuer()},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "the request object contains invalid claims", err)
	}

	return nil
}

func validateCIBARequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "grant ciba not allowed")
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(req.Scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	if req.ClientNotificationToken == "" && c.CIBATokenDeliveryMode.IsNotificationMode() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_notification_token is required")
	}

	if len(req.ClientNotificationToken) > 1024 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_notification_token is too long")
	}

	if req.UserCode != "" && (!ctx.CIBAUserCodeIsEnabled || !c.CIBAUserCodeIsEnabled) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "user_code is not allowed")
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

	if req.LoginTokenHint != "" {
		numberOfHints++
	}

	if req.IDTokenHint != "" {
		numberOfHints++
	}

	if numberOfHints != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "only one hint parameter must be informed")
	}

	return nil
}
