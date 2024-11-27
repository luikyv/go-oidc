package authorize

import (
	"errors"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initAuth(ctx oidc.Context, req request) error {

	if req.ClientID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	c, err := ctx.Client(req.ClientID)
	if err != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	// Check that the client is allowed to call the authorization endpoint.
	if !slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "client not allowed")
	}

	if err := initAuthNoRedirect(ctx, c, req); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func initAuthNoRedirect(ctx oidc.Context, client *goidc.Client, req request) error {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, session)
}

func continueAuth(ctx oidc.Context, callbackID string) error {

	session, err := ctx.AuthnSessionByCallbackID(callbackID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return err
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func initAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	session, err := authnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	policy, ok := ctx.AvailablePolicy(client, session)
	if !ok {
		return nil, newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"no policy available", session.AuthorizationParameters)
	}

	if session.Nonce != "" {
		session.SetIDTokenClaim(goidc.ClaimNonce, session.Nonce)
	}
	session.PolicyID = policy.ID
	session.CallbackID = callbackID()
	session.PushedAuthReqID = ""
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.AuthnSessionTimeoutSecs
	if session.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(session.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&session.IDTokenHintClaims)
	}
	return session, nil
}

func authnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {

	if shouldUsePAR(ctx, req.AuthorizationParameters, client) {
		return authnSessionWithPAR(ctx, req, client)
	}

	// The jar requirement comes after the par one, because the client may have
	// sent the jar during par.
	if shouldUseJAR(ctx, req.AuthorizationParameters, client) {
		return authnSessionWithJAR(ctx, req, client)
	}

	return simpleAuthnSession(ctx, req, client)
}

func shouldUsePAR(
	ctx oidc.Context,
	req goidc.AuthorizationParameters,
	c *goidc.Client,
) bool {
	if !ctx.PARIsEnabled {
		return false
	}
	return ctx.PARIsRequired || c.PARIsRequired || strings.HasPrefix(req.RequestURI, parRequestURIPrefix)
}

func authnSessionWithPAR(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {

	if req.RequestURI == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid request_uri")
	}

	if err := validateRequestWithPAR(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if dErr := ctx.DeleteAuthnSession(session.ID); dErr != nil {
			return nil, dErr
		}
		return nil, err
	}

	// For FAPI 2.0, only the parameters sent during PAR are considered.
	if ctx.Profile == goidc.ProfileFAPI2 {
		return session, nil
	}

	// For OIDC, the parameters sent in the authorization endpoint are merged
	// with the ones sent during PAR.
	session.AuthorizationParameters = mergeParams(session.AuthorizationParameters,
		req.AuthorizationParameters)
	return session, nil
}

func authnSessionWithJAR(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	var jar request
	var err error
	switch {
	case req.RequestObject != "":
		jar, err = jarFromRequestObject(ctx, req.RequestObject, client)
	case req.RequestURI != "":
		jar, err = jarFromRequestURI(ctx, req.RequestURI, client)
	default:
		err = goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"request object is required")
	}
	if err != nil {
		return nil, err
	}

	if err := validateRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	session.AuthorizationParameters = mergeParams(session.AuthorizationParameters,
		req.AuthorizationParameters)
	return session, nil
}

func simpleAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	if err := validateRequest(ctx, req, client); err != nil {
		return nil, err
	}
	return newAuthnSession(req.AuthorizationParameters, client), nil
}

func authorizationCode() string {
	return strutil.Random(authorizationCodeLength)
}

func callbackID() string {
	return strutil.Random(callbackIDLength)
}

func authenticate(ctx oidc.Context, session *goidc.AuthnSession) error {
	policy := ctx.Policy(session.PolicyID)
	switch status, err := policy.Authenticate(ctx.Response, ctx.Request, session); status {
	case goidc.StatusSuccess:
		return finishFlowSuccessfully(ctx, session)
	case goidc.StatusInProgress:
		return stopFlowInProgress(ctx, session)
	default:
		return finishFlowWithFailure(ctx, session, err)
	}
}

func finishFlowWithFailure(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	err error,
) error {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return redirectionErrorf(goidc.ErrorCodeInternalError,
			"internal error", session.AuthorizationParameters, err)
	}

	var oidcErr goidc.Error
	if errors.As(err, &oidcErr) {
		return newRedirectionError(oidcErr.Code,
			oidcErr.Description, session.AuthorizationParameters)
	}

	if err != nil {
		return newRedirectionError(goidc.ErrorCodeAccessDenied,
			err.Error(), session.AuthorizationParameters)
	}

	return newRedirectionError(goidc.ErrorCodeAccessDenied,
		"access denied", session.AuthorizationParameters)
}

func stopFlowInProgress(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) error {
	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
	}

	return nil
}

func finishFlowSuccessfully(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) error {

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return redirectionErrorf(goidc.ErrorCodeInternalError,
			"could not load the client", session.AuthorizationParameters, err)
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return err
	}

	redirectParams := response{
		authorizationCode: session.AuthCode,
		state:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grantInfo, err := implicitGrantInfo(ctx, session)
		if err != nil {
			return err
		}

		token, err := token.Make(ctx, grantInfo, client)
		if err != nil {
			return redirectionErrorf(goidc.ErrorCodeInternalError,
				"could not generate the access token", session.AuthorizationParameters, err)
		}

		redirectParams.accessToken = token.Value
		redirectParams.tokenType = token.Type
		if err := generateImplicitGrantSession(ctx, grantInfo, token); err != nil {
			return err
		}
	}

	if strutil.ContainsOpenID(session.GrantedScopes) &&
		session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idTokenOptions := token.IDTokenOptions{
			Subject:                 session.Subject,
			AdditionalIDTokenClaims: session.AdditionalIDTokenClaims,
			AccessToken:             redirectParams.accessToken,
			AuthorizationCode:       session.AuthCode,
			State:                   session.State,
		}

		redirectParams.idToken, err = token.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return redirectionErrorf(goidc.ErrorCodeInternalError,
				"could not generate the id token", session.AuthorizationParameters, err)
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) error {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it
		// for an access token, so we don't keep the session anymore.
		return ctx.DeleteAuthnSession(session.ID)
	}

	session.AuthCode = authorizationCode()
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + authorizationCodeLifetimeSecs
	// Make sure the session won't be reached anymore from the callback endpoint.
	session.CallbackID = ""

	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
	}

	return nil
}

func generateImplicitGrantSession(
	ctx oidc.Context,
	grantInfo goidc.GrantInfo,
	accessToken token.Token,
) error {

	grantSession := token.NewGrantSession(grantInfo, accessToken)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return err
	}

	return nil
}

func implicitGrantInfo(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) (
	goidc.GrantInfo,
	error,
) {
	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantImplicit,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		ActiveScopes:             session.GrantedScopes,
		GrantedScopes:            session.GrantedScopes,
		GrantedAuthDetails:       session.GrantedAuthDetails,
		ActiveResources:          session.GrantedResources,
		GrantedResources:         session.GrantedResources,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    session.AdditionalTokenClaims,
	}

	setPoPForImplicitGrant(ctx, &grantInfo, session)

	return grantInfo, nil
}

func setPoPForImplicitGrant(
	ctx oidc.Context,
	grantInfo *goidc.GrantInfo,
	session *goidc.AuthnSession,
) {
	if !ctx.DPoPIsEnabled {
		return
	}

	// Default to the JWK thumbprint stored in the session (e.g., from a previous PAR).
	// If not available, fallback to the thumbprint provided via the dpop_jkt parameter.
	grantInfo.JWKThumbprint = session.JWKThumbprint
	if grantInfo.JWKThumbprint == "" {
		grantInfo.JWKThumbprint = session.DPoPJKT
	}

	// TODO: Should the token be bound with tls cert if the client used mtls during /par?
	// It could be an one-time self signed certificate the client wants to use for binding.
}
