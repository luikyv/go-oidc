package authorize

import (
	"errors"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/federation"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func pushAuth(ctx oidc.Context, req request) (parResponse, error) {
	var shouldRegisterClient bool
	c, err := func() (*goidc.Client, error) {
		if !ctx.OpenIDFedIsEnabled {
			return client.Authenticated(ctx, client.AuthnContextToken)
		}

		if !slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeAutomatic) {
			return client.Authenticated(ctx, client.AuthnContextToken)
		}

		id, err := client.ExtractID(ctx)
		if err != nil {
			return nil, err
		}

		if !strutil.IsURL(id) {
			return client.Authenticated(ctx, client.AuthnContextToken)
		}

		c, err := client.Authenticated(ctx, client.AuthnContextToken)
		if err != nil {
			if !errors.Is(err, goidc.ErrNotFound) {
				return nil, err
			}
			shouldRegisterClient = true
			return federationClientForPAR(ctx, id, req)
		}

		if c.ExpiresAtTimestamp != 0 && timeutil.TimestampNow() > c.ExpiresAtTimestamp {
			shouldRegisterClient = true
			return federationClientForPAR(ctx, id, req)
		}

		return c, nil
	}()
	if err != nil {
		return parResponse{}, err
	}

	as, err := func() (*goidc.AuthnSession, error) {
		jar := ctx.JARIsEnabled && (ctx.JARIsRequired || c.JARIsRequired || req.RequestObject != "")
		if jar {
			if req.RequestObject == "" {
				return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "request object is required")
			}

			jar, err := jarFromRequestObject(ctx, req.RequestObject, c)
			if err != nil {
				return nil, err
			}

			if err := validatePushedRequestWithJAR(ctx, req, jar, c); err != nil {
				return nil, err
			}

			return &goidc.AuthnSession{
				ID:                      ctx.AuthnSessionID(),
				Status:                  goidc.StatusInProgress,
				PushedAuthReqID:         parRequestURIPrefix + ctx.PARID(),
				ClientID:                c.ID,
				AuthorizationParameters: jar.AuthorizationParameters,
				CreatedAtTimestamp:      timeutil.TimestampNow(),
				ExpiresAtTimestamp:      timeutil.TimestampNow() + ctx.PARLifetimeSecs,
				JWKThumbprint:           dpopThumbprintForPAR(ctx, req),
				ClientCertThumbprint:    tlsThumbprint(ctx),
				Store:                   make(map[string]any),
			}, nil
		}

		if err := validateSimplePushedRequest(ctx, req, c); err != nil {
			return nil, err
		}

		return &goidc.AuthnSession{
			ID:                      ctx.AuthnSessionID(),
			Status:                  goidc.StatusInProgress,
			PushedAuthReqID:         parRequestURIPrefix + ctx.PARID(),
			ClientID:                c.ID,
			AuthorizationParameters: req.AuthorizationParameters,
			CreatedAtTimestamp:      timeutil.TimestampNow(),
			ExpiresAtTimestamp:      timeutil.TimestampNow() + ctx.PARLifetimeSecs,
			JWKThumbprint:           dpopThumbprintForPAR(ctx, req),
			ClientCertThumbprint:    tlsThumbprint(ctx),
			Store:                   make(map[string]any),
		}, nil
	}()
	if err != nil {
		return parResponse{}, err
	}

	if err := ctx.PARHandleSession(as, c); err != nil {
		return parResponse{}, err
	}

	if shouldRegisterClient {
		if err := ctx.SaveClient(c); err != nil {
			return parResponse{}, err
		}
	}

	if err := ctx.SaveAuthnSession(as); err != nil {
		return parResponse{}, err
	}

	return parResponse{
		RequestURI: as.PushedAuthReqID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}, nil
}

func dpopThumbprintForPAR(ctx oidc.Context, req request) string {
	if !ctx.DPoPIsEnabled {
		return ""
	}
	if dpopJWT, ok := dpop.JWT(ctx); ctx.DPoPIsEnabled && ok {
		return dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}
	return req.DPoPJKT
}

func tlsThumbprint(ctx oidc.Context) string {
	if clientCert, err := ctx.ClientCert(); ctx.MTLSTokenBindingIsEnabled && err == nil {
		return hashutil.Thumbprint(string(clientCert.Raw))
	}
	return ""
}

func federationClientForPAR(ctx oidc.Context, id string, req request) (*goidc.Client, error) {
	var opts *federation.Options
	if ctx.JARIsEnabled && req.RequestObject != "" {
		opts = &federation.Options{
			TrustChain: jarTrustChain(req.RequestObject, ctx.JARSigAlgs),
		}
	}

	c, err := federation.Client(ctx, id, opts)
	if err != nil {
		return nil, err
	}

	jwksIsUsed := ctx.JARIsEnabled && req.RequestObject != ""
	jwksIsUsed = jwksIsUsed || c.TokenAuthnMethod == goidc.AuthnMethodPrivateKeyJWT
	jwksIsUsed = jwksIsUsed || c.TokenAuthnMethod == goidc.AuthnMethodSelfSignedTLS
	if !jwksIsUsed {
		return nil, goidc.NewError(goidc.ErrorCodeAccessDenied,
			"asymmetric cryptography must be used to authenticate requests when using automatic registration")
	}

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeAutomatic) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the client is not registered for automatic registration")
	}

	if err := client.Authenticate(ctx, c, client.AuthnContextToken); err != nil {
		return nil, err
	}

	return c, nil
}
