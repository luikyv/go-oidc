package authorize

import (
	"fmt"
	"strings"
	"time"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func pushAuth(
	ctx *oidc.Context,
	req PushedRequest,
) (
	PushedResponse,
	oidc.Error,
) {

	c, oauthErr := client.Authenticated(ctx, req.AuthnRequest)
	if oauthErr != nil {
		return PushedResponse{}, oidc.NewError(oidc.ErrorCodeInvalidClient,
			"client not authenticated")
	}

	session, oauthErr := pushAuthnSession(ctx, req, c)
	if oauthErr != nil {
		return PushedResponse{}, oauthErr
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return PushedResponse{}, err
	}
	return PushedResponse{
		RequestURI: session.RequestURI,
		ExpiresIn:  ctx.PAR.LifetimeSecs,
	}, nil
}

func pushAuthnSession(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	session, oauthErr := pushedAuthnSession(ctx, req, client)
	if oauthErr != nil {
		return nil, oauthErr
	}

	reqURI, err := requestURI()
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInternalError,
			"could not generate the request uri")
	}
	session.RequestURI = reqURI
	session.ExpiresAtTimestamp = time.Now().Unix() + ctx.PAR.LifetimeSecs

	return session, nil
}

func pushedAuthnSession(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if shouldUseJAR(ctx, req.AuthorizationParameters, client) {
		return pushedAuthnSessionWithJAR(ctx, req, client)
	}
	return simplePushedAuthnSession(ctx, req, client)
}

func simplePushedAuthnSession(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if err := validatePushedRequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = protectedParams(ctx)
	return session, nil
}

func pushedAuthnSessionWithJAR(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {

	if req.RequestObject == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest,
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

func protectedParams(ctx *oidc.Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.FormData() {
		if strings.HasPrefix(param, protectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func requestURI() (string, error) {
	s, err := strutil.Random(requestURILength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", s), nil
}
