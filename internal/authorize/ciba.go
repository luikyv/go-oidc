package authorize

import (
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/clientutil"
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
	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return cibaResponse{}, err
	}

	session, err := cibaAuthnSession(ctx, req, client)
	if err != nil {
		return cibaResponse{}, err
	}

	if err := ctx.InitBackAuth(session); err != nil {
		return cibaResponse{}, err
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return cibaResponse{}, err
	}

	resp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		ExpiresIn: session.ExpiresAtTimestamp - timeutil.TimestampNow(),
	}

	if client.CIBATokenDeliveryMode.IsPollableMode() {
		resp.Interval = ctx.CIBAPollingIntervalSecs
	}

	return resp, nil
}

func cibaAuthnSession(ctx oidc.Context, req request, client *goidc.Client) (*goidc.AuthnSession, error) {
	var session *goidc.AuthnSession
	var err error
	if shouldUseJARDuringCIBA(ctx, req.AuthorizationParameters, client) {
		session, err = cibaAuthnSessionWithJAR(ctx, req, client)
	} else {
		session, err = simpleCIBAAuthnSession(ctx, req, client)
	}
	if err != nil {
		return nil, err
	}

	session.CIBAAuthID = ctx.CIBAAuthReqID()
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.CIBADefaultSessionLifetimeSecs
	if session.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(session.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&session.IDTokenHintClaims)
	}

	// Store binding information only for CIBA push mode.
	// For other modes, binding occurs at the token endpoint.
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
		setPoPForCIBAPushMode(ctx, session)
	}

	return session, nil
}

func shouldUseJARDuringCIBA(ctx oidc.Context, req goidc.AuthorizationParameters, c *goidc.Client) bool {
	if !ctx.CIBAJARIsEnabled {
		return false
	}
	return ctx.CIBAJARIsRequired || c.CIBAJARSigAlg != "" || req.RequestObject != ""
}

func simpleCIBAAuthnSession(ctx oidc.Context, req request, client *goidc.Client) (*goidc.AuthnSession, error) {
	if err := validateCIBARequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(ctx, req.AuthorizationParameters, client)
	return session, nil
}

func cibaAuthnSessionWithJAR(ctx oidc.Context, req request, client *goidc.Client) (*goidc.AuthnSession, error) {

	if req.RequestObject == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	jar, err := cibaJARFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return nil, err
	}

	if err := validateCIBARequest(ctx, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(ctx, jar.AuthorizationParameters, client)
	return session, nil
}

func cibaJARFromRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
	jarAlgorithms := cibaJARAlgorithms(ctx, c)
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request object", err)
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := clientutil.JWKByKeyID(ctx, c, parsedToken.Headers[0].KeyID)
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

func validateCIBAJARClaims(ctx oidc.Context, claims jwt.Claims, client *goidc.Client) error {
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
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "the request object contains invalid claims", err)
	}

	return nil
}

func cibaJARAlgorithms(ctx oidc.Context, client *goidc.Client) []goidc.SignatureAlgorithm {
	if client.CIBAJARSigAlg != "" {
		return []goidc.SignatureAlgorithm{client.CIBAJARSigAlg}
	}
	return ctx.CIBAJARSigAlgs
}

func validateCIBARequest(ctx oidc.Context, req request, client *goidc.Client) error {

	if !slices.Contains(client.GrantTypes, goidc.GrantCIBA) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "grant ciba not allowed")
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(req.Scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	if req.ClientNotificationToken == "" && client.CIBATokenDeliveryMode.IsNotificationMode() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_notification_token is required")
	}

	if len(req.ClientNotificationToken) > 1024 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_notification_token is too long")
	}

	if req.UserCode != "" && (!ctx.CIBAUserCodeIsEnabled || !client.CIBAUserCodeIsEnabled) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "user_code is not allowed")
	}

	if err := validateCIBAHints(ctx, req, client); err != nil {
		return err
	}

	if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, client); err != nil {
		return err
	}

	// Validate token binding rules only for CIBA push mode.
	// For other modes, token binding occurs at the token endpoint.
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
		if err := token.ValidateBinding(ctx, client, nil); err != nil {
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

func setPoPForCIBAPushMode(ctx oidc.Context, session *goidc.AuthnSession) {
	dpopJWT, ok := dpop.JWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		session.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}

	clientCert, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err == nil {
		session.ClientCertThumbprint = hashutil.Thumbprint(string(clientCert.Raw))
	}
}
