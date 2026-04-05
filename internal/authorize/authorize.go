package authorize

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/federation"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initAuth(ctx oidc.Context, req request) error {
	if req.ClientID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	var shouldRegisterClient bool
	c, err := func() (*goidc.Client, error) {
		if !ctx.OpenIDFedIsEnabled {
			return ctx.Client(req.ClientID)
		}

		if !slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeAutomatic) {
			return ctx.Client(req.ClientID)
		}

		if !strutil.IsURL(req.ClientID) {
			return ctx.Client(req.ClientID)
		}

		c, err := ctx.Client(req.ClientID)
		if err != nil {
			if !errors.Is(err, goidc.ErrNotFound) {
				return nil, err
			}
			shouldRegisterClient = true
			return federationClient(ctx, req)
		}

		if c.ExpiresAtTimestamp != 0 && timeutil.TimestampNow() > c.ExpiresAtTimestamp {
			shouldRegisterClient = true
			return federationClient(ctx, req)
		}

		return c, nil
	}()
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

	as, err := func() (*goidc.AuthnSession, error) {
		par := ctx.PARIsEnabled &&
			(ctx.PARIsRequired || c.PARIsRequired || strings.HasPrefix(req.RequestURI, parRequestURIPrefix))
		if par {
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

		// The jar requirement comes after the par one, because the client may have sent the jar during par.
		jar := ctx.JARIsEnabled &&
			(ctx.JARIsRequired || c.JARIsRequired || req.RequestObject != "" || (ctx.JARByReferenceIsEnabled && req.RequestURI != ""))
		if jar {
			var jar request
			switch {
			case req.RequestObject != "":
				jar, err = jarFromRequestObject(ctx, req.RequestObject, c)
				if err != nil {
					return nil, err
				}
			case ctx.JARByReferenceIsEnabled && req.RequestURI != "":
				jar, err = jarFromRequestURI(ctx, req.RequestURI, c)
				if err != nil {
					return nil, err
				}
			default:
				return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request object is required")
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

		if err := validateRequest(ctx, req, c); err != nil {
			return nil, err
		}
		return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
	}()
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

	if ctx.VCIsEnabled {
		issuer, configIDs, err := vc.Resolve(ctx, vc.Request{
			Scopes:    as.Scopes,
			Details:   as.AuthDetails,
			Resources: as.Resources,
		})
		if err != nil {
			return redirectError(ctx, err, c)
		}
		if len(configIDs) > 0 {
			as.VCInfo = &struct {
				Issuer           string                    `json:"issuer"`
				ConfigurationIDs []goidc.VCConfigurationID `json:"configuration_ids"`
			}{
				Issuer:           issuer.ID,
				ConfigurationIDs: configIDs,
			}
		}
	}

	if shouldRegisterClient {
		if err := ctx.SaveClient(c); err != nil {
			return redirectError(ctx, err, c)
		}
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
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return err
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func authenticate(ctx oidc.Context, as *goidc.AuthnSession) error {
	policy := ctx.Policy(as.PolicyID)
	switch status, err := policy.Authenticate(ctx.Response, ctx.Request, as); status {
	case goidc.StatusSuccess:
		return finishFlow(ctx, as)
	case goidc.StatusInProgress:
		// TODO: How to avoid saving if nothing changed?
		return ctx.SaveAuthnSession(as)
	default:
		return finishFlowWithFailure(ctx, as, err)
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

func finishFlow(ctx oidc.Context, as *goidc.AuthnSession) error {
	c, err := ctx.Client(as.ClientID)
	if err != nil {
		return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not load the client", as.AuthorizationParameters, err)
	}

	if as.ResponseType.Contains(goidc.ResponseTypeCode) {
		as.AuthCode = ctx.AuthorizationCode()
		as.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.AuthorizationCodeLifetimeSecs
		// Make sure the session won't be reached anymore from the callback endpoint.
		as.CallbackID = ""
		// Make sure the session won't be reached anymore with the request URI.
		as.PushedAuthReqID = ""
		if err := ctx.SaveAuthnSession(as); err != nil {
			return err
		}
	} else {
		// The client didn't request an auth code to later exchange for an access token.
		if err := ctx.DeleteAuthnSession(as.ID); err != nil {
			return err
		}
	}

	redirectParams := response{
		authorizationCode: as.AuthCode,
		state:             as.State,
	}
	if as.ResponseType.IsImplicit() {
		grant, err := token.NewGrant(ctx, c, token.GrantOptions{
			Type:        goidc.GrantImplicit,
			Subject:     as.Subject,
			ClientID:    as.ClientID,
			Scopes:      as.GrantedScopes,
			Nonce:       as.Nonce,
			AuthDetails: as.GrantedAuthDetails,
			Resources:   as.GrantedResources,
			JWKThumbprint: func() string {
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
			}(),
			Store: as.Store,
		})
		if err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the grant", as.AuthorizationParameters, err)
		}

		if as.ResponseType.Contains(goidc.ResponseTypeToken) {
			tkn, tokenValue, err := token.Issue(ctx, grant, c, nil)
			if err != nil {
				return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the access token", as.AuthorizationParameters, err)
			}
			redirectParams.accessToken = tokenValue
			redirectParams.tokenType = tkn.Type
		}

		if strutil.ContainsOpenID(as.GrantedScopes) && as.ResponseType.Contains(goidc.ResponseTypeIDToken) {
			idToken, err := token.MakeIDToken(ctx, c, token.IDTokenOptions{
				Subject:           as.Subject,
				Nonce:             as.Nonce,
				AccessToken:       redirectParams.accessToken,
				AuthorizationCode: as.AuthCode,
				State:             as.State,
				Claims:            ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the id token", as.AuthorizationParameters, err)
			}
			redirectParams.idToken = idToken
		}
	}

	return redirectResponse(ctx, c, as.AuthorizationParameters, redirectParams)
}

func federationClient(ctx oidc.Context, req request) (*goidc.Client, error) {
	jwksIsUsed := ctx.JARIsEnabled && req.RequestObject != ""
	if !jwksIsUsed {
		return nil, goidc.NewError(goidc.ErrorCodeAccessDenied,
			"asymmetric cryptography must be used to authenticate requests when using automatic registration")
	}

	c, err := federation.Client(ctx, req.ClientID, &federation.Options{
		TrustChain: jarTrustChain(req.RequestObject, ctx.JARSigAlgs),
	})
	if err != nil {
		return nil, err
	}

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeAutomatic) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the client is not registered for automatic registration")
	}

	return c, nil
}
