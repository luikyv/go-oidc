package authorize

import (
	"fmt"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
type deviceResponse struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

// main device code interface

func initDeviceAuth(ctx oidc.Context, req request) (deviceResponse, error) {
	c, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		// the error is already wrapped
		return deviceResponse{}, err
	}

	if !clientutil.AreScopesAllowed(c, ctx.Scopes, req.Scopes) {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	// check that the client is allowed to call the device code endpoint.
	if !clientutil.IsGrantAllowed(c, goidc.GrantDeviceCode) {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidClient, "client not allowed")
	}

	as, err := initDeviceAuthnSession(ctx, req, c)
	if err != nil {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInternalError, "could not initialize the session", err)
	}

	// store the session here. needed by token and device endpoints.
	if err := ctx.SaveAuthnSession(as); err != nil {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}

	return generateDeviceResponse(ctx, as), nil
}

func startDeviceAuth(ctx oidc.Context, req request) error {
	// no user code, just render the verification page.
	if req.UserCode == "" {
		if err := ctx.HandleUserCodeFunc(ctx.Response, ctx.Request); err != nil {
			// return user error as is
			return err
		}
		return nil
	}

	session, err := ctx.AuthnSessionByUserCode(req.UserCode)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}
	// delete user code from session to prevent reuse.
	session.UserCode = ""

	if err := ctx.SaveAuthnSession(session); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}

	if err := authenticate(ctx, session); err != nil {
		// return user error as is
		return err
	}
	return nil
}

func continueDeviceAuth(ctx oidc.Context, callbackID string) error {
	session, err := ctx.AuthnSessionByDeviceCallbackID(callbackID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not handle the failed device auth", err)
	}

	if err := authenticate(ctx, session); err != nil {
		// return user error as is
		return err
	}
	return nil
}

// device code authentication interface

func finishDeviceFlowWithFailure(ctx oidc.Context, session *goidc.AuthnSession, err error) error {
	// we do not delete the session here to give a chance to the /token endpoint that is being
	// polled to return access_denied to the client. delete will be done by the token endpoint
	session.Authorized = false
	session.AuthorizationPending = false
	session.DeviceCallbackID = ""
	if err := ctx.SaveAuthnSession(session); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}
	// return the original error to be handled by renderError as is
	return err
}

func finishDeviceFlowSuccessfully(ctx oidc.Context, session *goidc.AuthnSession) error {
	// deleting the session will be done by the /token endpoint that is being polled
	session.Authorized = true
	session.AuthorizationPending = false
	session.DeviceCallbackID = ""
	if err := ctx.SaveAuthnSession(session); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}
	return nil
}

// helpers

func generateDeviceResponse(ctx oidc.Context, as *goidc.AuthnSession) deviceResponse {
	verURI := ctx.BaseURL() + ctx.EndpointDevice
	verCompURI := ""
	if ctx.DeviceAuthorizationEnableVerificationURIComplete {
		verCompURI = verURI + "?user_code=" + as.UserCode
	}
	return deviceResponse{
		DeviceCode:              as.DeviceCode,
		UserCode:                as.UserCode,
		VerificationURI:         verURI,
		VerificationURIComplete: verCompURI,
		ExpiresIn:               ctx.DeviceAuthorizationLifetimeSecs,
		Interval:                ctx.DeviceAuthorizationPollingIntervalSecs,
	}
}

func initDeviceAuthnSession(ctx oidc.Context, req request, client *goidc.Client) (*goidc.AuthnSession, error) {
	session := newAuthnSession(req.AuthorizationParameters, client)
	session.CreatedAtTimestamp = timeutil.TimestampNow()
	session.ExpiresAtTimestamp = session.CreatedAtTimestamp + ctx.DeviceAuthorizationLifetimeSecs
	session.AuthorizationPending = true
	session.DeviceCallbackID = callbackID()
	policy, ok := ctx.AvailablePolicy(client, session)
	if !ok {
		// TODO: better error
		return nil, fmt.Errorf("could not find a suitable policy for the client")
	}
	session.PolicyID = policy.ID

	deviceCode, err := ctx.GenerateDeviceCodeFunc()
	if err != nil {
		return nil, fmt.Errorf("could not generate device code: %w", err)
	}
	session.DeviceCode = deviceCode

	userCode, err := ctx.GenerateUserCodeFunc()
	if err != nil {
		return nil, fmt.Errorf("could not generate user code: %w", err)
	}
	session.UserCode = userCode

	return session, nil
}
