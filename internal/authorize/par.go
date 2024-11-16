package authorize

import (
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func pushAuth(
	ctx oidc.Context,
	req request,
) (
	pushedResponse,
	error,
) {

	c, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return pushedResponse{}, err
	}

	session, err := pushedAuthnSession(ctx, req, c)
	if err != nil {
		return pushedResponse{}, err
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return pushedResponse{}, err
	}
	return pushedResponse{
		RequestURI: session.PushedAuthReqID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}, nil
}

// pushedAuthnSession builds a new authentication session and saves it.
func pushedAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	var session *goidc.AuthnSession
	var err error
	if shouldUseJARDuringPAR(ctx, req.AuthorizationParameters, client) {
		session, err = pushedAuthnSessionWithJAR(ctx, req, client)
	} else {
		session, err = simplePushedAuthnSession(ctx, req, client)
	}
	if err != nil {
		return nil, err
	}

	session.PushedAuthReqID = requestURI()
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.PARLifetimeSecs

	setPoPForPAR(ctx, session)

	return session, nil
}

func simplePushedAuthnSession(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	if err := validatePushedRequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(req.AuthorizationParameters, client)
	return session, nil
}

func pushedAuthnSessionWithJAR(
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

	jar, err := jarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return nil, err
	}

	if err := validatePushedRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	return session, nil
}

func requestURI() string {
	return parRequestURIPrefix + strutil.Random(parRequestURILength)
}

func setPoPForPAR(ctx oidc.Context, session *goidc.AuthnSession) {
	if ctx.DPoPIsEnabled {
		session.JWKThumbprint = session.DPoPJKT
		dpopJWT, ok := dpop.JWT(ctx)
		if ok {
			session.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
		}
	}

	clientCert, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err == nil {
		session.ClientCertThumbprint = hashutil.Thumbprint(string(clientCert.Raw))
	}
}
