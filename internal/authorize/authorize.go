package authorize

import (
	"errors"
	"fmt"
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
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", errors.New("client_id is required"))
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

		if c.ExpiresAt != 0 && timeutil.TimestampNow() >= c.ExpiresAt {
			shouldRegisterFedClient = true
			return federationClient(ctx, req)
		}

		return c, nil
	}()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", fmt.Errorf("could not load the client: %w", err))
	}

	// Check that the client is allowed to call the authorization endpoint.
	if !slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the client is not allowed to use the authorization endpoint grant types"))
	}

	as, err := func() (*goidc.AuthnSession, error) {
		par := ctx.PARIsEnabled && (ctx.PARIsRequired || c.PARIsRequired || strings.HasPrefix(req.RequestURI, parRequestURIPrefix))
		if par {
			if req.RequestURI == "" {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request_uri is required"))
			}

			as, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(req.RequestURI, parRequestURIPrefix))
			if err != nil {
				if errors.Is(err, goidc.ErrNotFound) {
					return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the pushed authorization request identified by request_uri was not found"))
				}
				return nil, fmt.Errorf("could not load the pushed authorization request session: %w", err)
			}

			if err := validateRequestWithPAR(ctx, req, as, c); err != nil {
				as.Status = goidc.StatusFailure
				// If any of the parameters is invalid, we fail the session right away.
				if saveErr := ctx.AuthSaveSession(as); saveErr != nil {
					return nil, fmt.Errorf("could not save the invalid pushed authorization request session: %w", saveErr)
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
				jar, err = jarFromRequestObject(ctx, req.RequestObject, c, &jarOptions{
					// [OpenID Fed Connect 1.1 §12.1.1.1] jti is required in
					// request objects for automatic client registration.
					jtiIsRequired: shouldRegisterFedClient,
				})
				if err != nil {
					return nil, err
				}
			case ctx.JARByReferenceIsEnabled && req.RequestURI != "":
				jar, err = jarFromRequestURI(ctx, req.RequestURI, c)
				if err != nil {
					return nil, err
				}
			default:
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request object is required when JAR is enabled"))
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
		return redirectError(ctx, wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", as.AuthorizationParameters,
			errors.New("no authentication policy is available for the authorization request")), c)
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
			var oidcErr goidc.Error
			if errors.As(err, &oidcErr) {
				return redirectError(ctx, wrapRedirectionError(oidcErr.Code, oidcErr.Description, as.AuthorizationParameters, err), c)
			}
			return fmt.Errorf("could not resolve verifiable credential metadata for the authorization request: %w", err)
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
			return fmt.Errorf("could not save the federated client: %w", err)
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
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the authentication session was not found"))
		}
		return fmt.Errorf("could not load the authentication session: %w", err)
	}

	if timeutil.TimestampNow() >= as.ExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the authentication session has expired"))
	}

	// TODO: Review this.
	if as.ResponseMode.IsJSON() && ctx.RequestMethod() != http.MethodPost {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("json response mode requires an HTTP POST callback request"))
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return fmt.Errorf("could not load the client for the authentication session: %w", err)
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
		as.Status = goidc.StatusFailure
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not delete the authentication session with a missing policy id: %w", err)
		}
		return fmt.Errorf("the authentication session is missing the policy id")
	}

	switch status, authErr := ctx.Policy(as.PolicyID).Authenticate(ctx.Response, ctx.Request, as, c); status {
	case goidc.StatusSuccess:
		as.Status = goidc.StatusSuccess
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the completed authentication session: %w", err)
		}

		grant, err := token.NewGrant(ctx, c, token.GrantOptions{
			Type: func() goidc.GrantType {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return goidc.GrantImplicit
				}
				return goidc.GrantAuthorizationCode
			}(),
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
			return fmt.Errorf("could not generate the grant for the authentication session: %w", err)
		}

		redirectParams := response{
			authorizationCode: grant.AuthCode,
			state:             as.State,
		}
		if as.ResponseType.Contains(goidc.ResponseTypeToken) {
			tkn, tokenValue, err := token.Issue(ctx, grant, c, nil)
			if err != nil {
				return fmt.Errorf("could not generate the access token for the authentication session: %w", err)
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
				return fmt.Errorf("could not generate the id token for the authentication session: %w", err)
			}
			redirectParams.idToken = idToken
		}
		return redirectResponse(ctx, c, as.AuthorizationParameters, redirectParams)
	case goidc.StatusPending:
		as.Status = goidc.StatusPending
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the in-progress authentication session: %w", err)
		}
		return nil
	default:
		as.Status = goidc.StatusFailure
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the failed authentication session: %w", err)
		}

		var oidcErr goidc.Error
		if errors.As(authErr, &oidcErr) {
			return redirectionError{
				err:                     oidcErr,
				AuthorizationParameters: as.AuthorizationParameters,
			}
		}

		if authErr != nil {
			return wrapRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", as.AuthorizationParameters, authErr)
		}

		return newRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", as.AuthorizationParameters)
	}
}

func federationClient(ctx oidc.Context, req request) (*goidc.Client, error) {
	jwksIsUsed := ctx.JARIsEnabled && req.RequestObject != ""
	if !jwksIsUsed {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied",
			errors.New("automatic federation registration requires a signed request object"))
	}

	c, err := federation.Client(ctx, req.ClientID, &federation.Options{
		TrustChain: jarTrustChain(req.RequestObject, ctx.JARSigAlgs),
	})
	if err != nil {
		return nil, err
	}
	// TODO: Validate the jar alg for the client.

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeAutomatic) {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("the client is not registered for automatic federation registration"))
	}

	return c, nil
}
