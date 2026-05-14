package authorize

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
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

	var shouldRegisterFedClient bool
	c, err := func() (*goidc.Client, error) {
		if !ctx.OpenIDFedIsEnabled {
			return client.Client(ctx, req.ClientID)
		}

		if !slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeAutomatic) {
			return client.Client(ctx, req.ClientID)
		}

		if !strutil.IsURL(req.ClientID) {
			return client.Client(ctx, req.ClientID)
		}

		c, err := client.Client(ctx, req.ClientID)
		if err != nil {
			if !errors.Is(err, goidc.ErrNotFound) {
				return nil, err
			}
			shouldRegisterFedClient = true
			return federationClient(ctx, req)
		}

		if c.ExpiresAt != 0 && timeutil.TimestampNow() > c.ExpiresAt {
			shouldRegisterFedClient = true
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
		par := ctx.PARIsEnabled && (ctx.PARIsRequired || c.PARIsRequired || strings.HasPrefix(req.RequestURI, parRequestURIPrefix))
		if par {
			if req.RequestURI == "" {
				return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request_uri is required")
			}

			as, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(req.RequestURI, parRequestURIPrefix))
			if err != nil {
				return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
			}

			if err := validateRequestWithPAR(ctx, req, as, c); err != nil {
				// If any of the parameters is invalid, we delete the session right away.
				if deleteErr := ctx.AuthDeleteSession(as.ID); deleteErr != nil {
					return nil, deleteErr
				}
				return nil, err
			}

			// For FAPI, only the parameters sent during PAR are considered.
			if ctx.Profile.IsFAPI() {
				return as, nil
			}

			// For OIDC, the parameters sent in the authorization endpoint are merged
			// with the ones sent during PAR.
			as.AuthorizationParameters = mergeParams(as.AuthorizationParameters, req.AuthorizationParameters)
			return as, nil
		}

		// The jar requirement comes after the par one, because the client may have sent the jar during par.
		jar := ctx.JARIsEnabled && (ctx.JARIsRequired || c.JARIsRequired || req.RequestObject != "" || (ctx.JARByReferenceIsEnabled && req.RequestURI != ""))
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

			as := newAuthnSession(ctx, jar.AuthorizationParameters, c)
			// For FAPI, only the parameters sent inside the JAR are considered.
			if ctx.Profile.IsFAPI() {
				return as, nil
			}

			// For OIDC, the parameters sent in the authorization endpoint are merged
			// with the ones sent inside the JAR.
			as.AuthorizationParameters = mergeParams(as.AuthorizationParameters, req.AuthorizationParameters)
			return as, nil
		}

		if err := validateRequest(ctx, req, c); err != nil {
			return nil, err
		}
		return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
	}()
	if err != nil {
		return redirectError(ctx, err, c)
	}

	policy, ok := ctx.AvailablePolicy(as, c)
	if !ok {
		return redirectError(ctx, newRedirectionError(goidc.ErrorCodeInvalidRequest, "no policy available", as.AuthorizationParameters), c)
	}

	as.PolicyID = policy.ID
	as.ExpiresAt = timeutil.TimestampNow() + ctx.AuthTimeoutSecs
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

	if shouldRegisterFedClient {
		if err := ctx.OpenIDFedSaveClient(c); err != nil {
			return redirectError(ctx, err, c)
		}
	}

	if err := authenticate(ctx, as, c); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func continueAuth(ctx oidc.Context, id string) error {
	as, err := ctx.AuthSession(id)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	// TODO: Review this.
	if as.ResponseMode.IsJSON() && ctx.RequestMethod() != http.MethodPost {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request method for json response mode")
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not load client", err)
	}

	if oauthErr := authenticate(ctx, as, c); oauthErr != nil {
		return redirectError(ctx, oauthErr, c)
	}

	return nil
}

func authenticate(ctx oidc.Context, as *goidc.AuthnSession, c *goidc.Client) error {
	// If the policy ID is missing, the callback endpoint was accessed without
	// first going through the authorization endpoint. This indicates an invalid
	// or incomplete authorization flow, so the session must be deleted and an
	// error returned.
	if as.PolicyID == "" {
		if err := ctx.AuthDeleteSession(as.ID); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", err)
		}
		return goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", errors.New("the policy id is not set in the session"))
	}

	switch status, authErr := ctx.Policy(as.PolicyID).Authenticate(ctx.Response, ctx.Request, as, c); status {
	case goidc.StatusSuccess:
		if err := ctx.AuthDeleteSession(as.ID); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "internal error", as.AuthorizationParameters, err)
		}

		grant, err := token.NewGrant(ctx, c, token.GrantOptions{
			Subject:     as.Subject,
			Username:    as.Username,
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
			AuthCode: func() string {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return ""
				}
				return ctx.AuthCode()
			}(),
			AuthCodeExpiresAt: func() int {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return 0
				}
				return timeutil.TimestampNow() + ctx.AuthCodeLifetimeSecs
			}(),
			AuthParams: as.AuthorizationParameters,
			Store:      as.Store,
		})
		if err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the grant", as.AuthorizationParameters, err)
		}

		redirectParams := response{
			authorizationCode: grant.AuthCode,
			state:             as.State,
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
				AuthorizationCode: grant.AuthCode,
				State:             as.State,
				Claims:            ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return wrapRedirectionError(goidc.ErrorCodeInternalError, "could not generate the id token", as.AuthorizationParameters, err)
			}
			redirectParams.idToken = idToken
		}
		return redirectResponse(ctx, c, as.AuthorizationParameters, redirectParams)
	case goidc.StatusInProgress:
		return ctx.AuthSaveSession(as)
	default:
		if err := ctx.AuthDeleteSession(as.ID); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInternalError, "internal error", as.AuthorizationParameters, err)
		}

		var oidcErr goidc.Error
		if errors.As(authErr, &oidcErr) {
			return newRedirectionError(oidcErr.Code, oidcErr.Description, as.AuthorizationParameters)
		}

		if authErr != nil {
			return newRedirectionError(goidc.ErrorCodeAccessDenied, authErr.Error(), as.AuthorizationParameters)
		}

		return newRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", as.AuthorizationParameters)
	}
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
	// TODO: Validate the jar alg for the client.

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeAutomatic) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the client is not registered for automatic registration")
	}

	return c, nil
}
