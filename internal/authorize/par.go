package authorize

import (
	"fmt"
	"strings"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func pushAuth(
	ctx *oidc.Context,
	req pushedRequest,
) (
	pushedResponse,
	error,
) {

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return pushedResponse{}, err
	}

	session, err := pushAuthnSession(ctx, req, c)
	if err != nil {
		return pushedResponse{}, err
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return pushedResponse{}, goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not store the pushed authentication session", err)
	}
	return pushedResponse{
		RequestURI: session.ReferenceID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}, nil
}

func pushAuthnSession(
	ctx *oidc.Context,
	req pushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	session, err := pushedAuthnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	reqURI, err := requestURI()
	if err != nil {
		return nil, err
	}
	session.ReferenceID = reqURI
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.PARLifetimeSecs

	return session, nil
}

func pushedAuthnSession(
	ctx *oidc.Context,
	req pushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	if shouldUseJAR(ctx, req.AuthorizationParameters, client) {
		return pushedAuthnSessionWithJAR(ctx, req, client)
	}
	return simplePushedAuthnSession(ctx, req, client)
}

func simplePushedAuthnSession(
	ctx *oidc.Context,
	req pushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
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
	req pushedRequest,
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
		return "", goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not generate the request uri", err)
	}
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", s), nil
}
