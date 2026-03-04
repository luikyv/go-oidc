package authorize

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
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

	c, err := client.Client(ctx, req.ClientID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", err)
	}

	// Check that the client is allowed to call the authorization endpoint.
	if !slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "client not allowed",
			errors.New("client is missing grant type to call the authorization endpoint"))
	}

	as, err := authnSession(ctx, req, c)
	if err != nil {
		return redirectError(ctx, err, c)
	}

	policy, ok := ctx.AvailablePolicy(c, as)
	if !ok {
		return redirectError(ctx, newRedirectionError(goidc.ErrorCodeInvalidRequest, "no policy available", as.AuthorizationParameters), c)
	}

	as.PolicyID = policy.ID
	as.CallbackID = ctx.CallbackID()
	as.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.AuthnSessionTimeoutSecs
	if as.IDTokenHint != "" {
		// The ID token hint was already validated.
		idToken, _ := jwt.ParseSigned(as.IDTokenHint, ctx.IDTokenSigAlgs)
		_ = idToken.UnsafeClaimsWithoutVerification(&as.IDTokenHintClaims)
	}

	if err := authenticate(ctx, as); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func continueAuth(ctx oidc.Context, callbackID string) error {

	session, err := ctx.AuthnSessionByCallbackID(callbackID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	if session.ResponseMode.IsJSON() && ctx.RequestMethod() != http.MethodPost {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request method for json response mode")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := client.Client(ctx, session.ClientID)
		if err != nil {
			return err
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func authnSession(ctx oidc.Context, req request, c *goidc.Client) (*goidc.AuthnSession, error) {

	par := ctx.PARIsEnabled &&
		(ctx.PARIsRequired || c.PARIsRequired || strings.HasPrefix(req.RequestURI, parRequestURIPrefix))
	if par {
		return authnSessionWithPAR(ctx, req, c)
	}

	// The jar requirement comes after the par one, because the client may have sent the jar during par.
	jar := ctx.JARIsEnabled &&
		(ctx.JARIsRequired || c.JARIsRequired || req.RequestObject != "" || (ctx.JARByReferenceIsEnabled && req.RequestURI != ""))
	if jar {
		return authnSessionWithJAR(ctx, req, c)
	}

	return simpleAuthnSession(ctx, req, c)
}

func authnSessionWithPAR(ctx oidc.Context, req request, c *goidc.Client) (*goidc.AuthnSession, error) {
	if req.RequestURI == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	if err := validateRequestWithPAR(ctx, req, session, c); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if dErr := ctx.DeleteAuthnSession(session.ID); dErr != nil {
			return nil, dErr
		}
		return nil, err
	}

	// For FAPI, only the parameters sent during PAR are considered.
	if ctx.Profile.IsFAPI() {
		return session, nil
	}

	// For OIDC, the parameters sent in the authorization endpoint are merged
	// with the ones sent during PAR.
	session.AuthorizationParameters = mergeParams(session.AuthorizationParameters, req.AuthorizationParameters)
	return session, nil
}

func authnSessionWithJAR(ctx oidc.Context, req request, c *goidc.Client) (*goidc.AuthnSession, error) {
	var jar request
	var err error
	switch {
	case req.RequestObject != "":
		jar, err = jarFromRequestObject(ctx, req.RequestObject, c)
	case ctx.JARByReferenceIsEnabled && req.RequestURI != "":
		jar, err = jarFromRequestURI(ctx, req.RequestURI, c)
	default:
		err = goidc.NewError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}
	if err != nil {
		return nil, err
	}

	if err := validateRequestWithJAR(ctx, req, jar, c); err != nil {
		return nil, err
	}

	session := newAuthnSession(ctx, jar.AuthorizationParameters, c)
	// For FAPI, only the parameters sent inside the JAR are considered.
	if ctx.Profile.IsFAPI() {
		return session, nil
	}

	// For OIDC, the parameters sent in the authorization endpoint are merged
	// with the ones sent inside the JAR.
	session.AuthorizationParameters = mergeParams(session.AuthorizationParameters, req.AuthorizationParameters)
	return session, nil
}

func simpleAuthnSession(ctx oidc.Context, req request, c *goidc.Client) (*goidc.AuthnSession, error) {
	if err := validateRequest(ctx, req, c); err != nil {
		return nil, err
	}
	return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
}

func authenticate(ctx oidc.Context, session *goidc.AuthnSession) error {
	policy := ctx.Policy(session.PolicyID)
	switch status, err := policy.Authenticate(ctx.Response, ctx.Request, session); status {
	case goidc.StatusSuccess:
		return finishFlow(ctx, session)
	case goidc.StatusInProgress:
		// TODO: How to avoid saving if nothing changed?
		return ctx.SaveAuthnSession(session)
	default:
		return finishFlowWithFailure(ctx, session, err)
	}
}

func finishFlowWithFailure(ctx oidc.Context, session *goidc.AuthnSession, err error) error {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return wrapRedirectionError(goidc.ErrorCodeInternalError, "internal error", session.AuthorizationParameters, err)
	}

	var oidcErr goidc.Error
	if errors.As(err, &oidcErr) {
		return newRedirectionError(oidcErr.Code, oidcErr.Description, session.AuthorizationParameters)
	}

	if err != nil {
		return newRedirectionError(goidc.ErrorCodeAccessDenied, err.Error(), session.AuthorizationParameters)
	}

	return newRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", session.AuthorizationParameters)
}

func finishFlow(ctx oidc.Context, session *goidc.AuthnSession) error {
	c, err := client.Client(ctx, session.ClientID)
	if err != nil {
		return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not load the client", session.AuthorizationParameters, err)
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return err
	}

	// Build the grant from the session upfront so it is available for both
	// access token issuance and ID token claims callbacks.
	grant := &goidc.Grant{
		Type:     goidc.GrantImplicit,
		Subject:  session.Subject,
		ClientID: session.ClientID,
		Scopes:   session.GrantedScopes,
		Nonce:    session.Nonce,
		Store:    session.Store,
		AuthDetails: func() []goidc.AuthorizationDetail {
			if ctx.RichAuthorizationIsEnabled {
				return session.GrantedAuthDetails
			}
			return nil
		}(),
		Resources: func() goidc.Resources {
			if ctx.ResourceIndicatorsIsEnabled {
				return session.GrantedResources
			}
			return nil
		}(),
		JWKThumbprint: dpopThumbprint(ctx, session),
	}

	redirectParams := response{
		authorizationCode: session.AuthCode,
		state:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grant.ID = ctx.GrantID()
		grant.CreatedAtTimestamp = timeutil.TimestampNow()

		if err := ctx.HandleGrant(grant); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not handle the grant", session.AuthorizationParameters, err)
		}

		opts := ctx.TokenOptions(grant, c)
		now := timeutil.TimestampNow()
		tkn := &goidc.Token{
			ID: func() string {
				if opts.Format == goidc.TokenFormatJWT {
					return ctx.JWTID()
				}
				return ctx.OpaqueToken()
			}(),
			GrantID:              grant.ID,
			Subject:              grant.Subject,
			ClientID:             grant.ClientID,
			Scopes:               grant.Scopes,
			AuthDetails:          grant.AuthDetails,
			Resources:            grant.Resources,
			JWKThumbprint:        grant.JWKThumbprint,
			ClientCertThumbprint: grant.ClientCertThumbprint,
			CreatedAtTimestamp:   now,
			ExpiresAtTimestamp:   now + opts.LifetimeSecs,
			Format:               opts.Format,
			SigAlg:               opts.JWTSigAlg,
		}
		tokenValue, err := token.Make(ctx, tkn, grant)
		if err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the access token", session.AuthorizationParameters, err)
		}

		redirectParams.accessToken = tokenValue
		redirectParams.tokenType = tokenType(tkn)

		if err := ctx.SaveGrant(grant); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not save the grant", session.AuthorizationParameters, err)
		}

		if err := ctx.SaveToken(tkn); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not save the token", session.AuthorizationParameters, err)
		}
	}

	if strutil.ContainsOpenID(session.GrantedScopes) && session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idToken, err := token.MakeIDToken(ctx, c, grant, token.IDTokenOptions{
			Subject:           session.Subject,
			Nonce:             session.Nonce,
			AccessToken:       redirectParams.accessToken,
			AuthorizationCode: session.AuthCode,
			State:             session.State,
		})
		if err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the id token", session.AuthorizationParameters, err)
		}
		redirectParams.idToken = idToken
	}

	return redirectResponse(ctx, c, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(ctx oidc.Context, session *goidc.AuthnSession) error {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it
		// for an access token, so we don't keep the session anymore.
		return ctx.DeleteAuthnSession(session.ID)
	}

	session.AuthCode = ctx.AuthorizationCode()
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.AuthorizationCodeLifetimeSecs
	// Make sure the session won't be reached anymore from the callback endpoint.
	session.CallbackID = ""
	// Make sure the session won't be reached anymore with the request URI.
	session.PushedAuthReqID = ""

	return ctx.SaveAuthnSession(session)
}

func dpopThumbprint(ctx oidc.Context, as *goidc.AuthnSession) string {
	if !ctx.DPoPIsEnabled {
		return ""
	}

	// Default to the JWK thumbprint stored in the session (e.g., from a previous PAR).
	// If not available, fallback to the thumbprint provided via the dpop_jkt parameter.
	if as.JWKThumbprint != "" {
		return as.JWKThumbprint
	}
	return as.DPoPJKT
	// TODO: Should the token be bound with tls cert if the client used mtls during /par?
	// It could be an one-time self signed certificate the client wants to use for binding.
}

func tokenType(tkn *goidc.Token) goidc.TokenType {
	if tkn.JWKThumbprint != "" {
		return goidc.TokenTypeDPoP
	}
	return goidc.TokenTypeBearer
}
