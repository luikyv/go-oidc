package authorize

import (
	"errors"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

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
		return cibaResponse{}, goidc.WrapError(goidc.ErrorCodeInternalError,
			"internal error", err)
	}

	resp := cibaResponse{
		AuthReqID: session.PushedAuthReqID,
		ExpiresIn: session.ExpiresAtTimestamp - timeutil.TimestampNow(),
	}

	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePoll {
		resp.Interval = ctx.CIBAPollingIntervalSecs
	}

	return resp, nil
}

func cibaAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
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

	session.PushedAuthReqID = uuid.NewString()
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.CIBADefaultSessionLifetimeSecs
	if session.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(session.IDTokenHint, ctx.UserSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&session.IDTokenHintClaims)
	}
	return session, nil
}

func shouldUseJARDuringCIBA(
	ctx oidc.Context,
	req goidc.AuthorizationParameters,
	c *goidc.Client,
) bool {
	if !ctx.CIBAJARIsEnabled {
		return false
	}
	return ctx.CIBAJARIsRequired || c.CIBAJARSigAlg != "" || req.RequestObject != ""
}

func simpleCIBAAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	if err := validateCIBARequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(req.AuthorizationParameters, client)
	return session, nil
}

func cibaAuthnSessionWithJAR(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {

	if req.RequestObject == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"request object is required")
	}

	jar, err := cibaJARFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return nil, err
	}

	if err := validateCIBARequest(ctx, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	return session, nil
}

func cibaJARFromRequestObject(
	ctx oidc.Context,
	reqObject string,
	c *goidc.Client,
) (
	request,
	error,
) {
	jarAlgorithms := cibaJARAlgorithms(ctx, c)
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"invalid request object", err)
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := clientutil.JWKByKeyID(ctx, c, parsedToken.Headers[0].KeyID)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not fetch the client public key", err)
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not extract claims from the request object", err)
	}

	if err := validateCIBAJARClaims(ctx, claims, c); err != nil {
		return request{}, err
	}

	return jarReq, nil
}

func validateCIBAJARClaims(
	ctx oidc.Context,
	claims jwt.Claims,
	client *goidc.Client,
) error {
	if claims.IssuedAt == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"claim 'iat' is required in the request object")
	}

	if claims.NotBefore == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"claim 'nbf' is required in the request object")
	}

	if claims.Expiry == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"claim 'exp' is required in the request object")
	}

	if claims.ID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"claim 'jti' is required in the request object")
	}

	if err := ctx.CheckJTI(claims.ID); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"invalid jti claim", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"the request object contains invalid claims", err)
	}

	return nil
}

func cibaJARAlgorithms(ctx oidc.Context, client *goidc.Client) []jose.SignatureAlgorithm {
	jarAlgorithms := ctx.CIBAJARSigAlgs
	if client.CIBAJARSigAlg != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.CIBAJARSigAlg}
	}
	return jarAlgorithms
}

func validateCIBARequest(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) error {

	if !slices.Contains(client.GrantTypes, goidc.GrantCIBA) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient,
			"grant ciba not allowed")
	}

	if !strutil.ContainsOpenID(req.Scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope,
			"scope openid is required")
	}

	if req.ClientNotificationToken == "" && client.CIBATokenDeliveryMode.IsNotificationMode() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"client_notification_token is required")
	}

	if len(req.ClientNotificationToken) > 1024 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"client_notification_token is too long")
	}

	if req.UserCode != "" && (!ctx.CIBAUserCodeIsEnabled || !client.CIBAUserCodeIsEnabled) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"user_code is not allowed")
	}

	if err := validateCIBAHints(ctx, req, client); err != nil {
		return err
	}

	if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, client); err != nil {
		// Convert the redirection error to a standard one.
		var redirectErr redirectionError
		if errors.As(err, &redirectErr) {
			return goidc.WrapError(redirectErr.code, redirectErr.desc, redirectErr)
		}
		return err
	}

	return nil
}

func validateCIBAHints(
	_ oidc.Context,
	req request,
	_ *goidc.Client,
) error {
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
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"only one hint parameter must be informed")
	}

	return nil
}
