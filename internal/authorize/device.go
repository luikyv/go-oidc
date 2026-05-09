package authorize

import (
	"errors"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type deviceResponse struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

func initDeviceAuth(ctx oidc.Context, req request) (deviceResponse, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return deviceResponse{}, err
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantDeviceCode) {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "urn:ietf:params:oauth:grant-type:device_code not allowed")
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(req.Scopes) {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, c); err != nil {
		return deviceResponse{}, err
	}

	as := newAuthnSession(ctx, req.AuthorizationParameters, c)

	policy, ok := ctx.AvailablePolicy(c, as)
	if !ok {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "no policy available")
	}

	as.ExpiresAtTimestamp = as.CreatedAtTimestamp + ctx.DeviceAuthLifetimeSecs
	as.CallbackID = ctx.CallbackID()
	as.PolicyID = policy.ID
	as.DeviceCode = ctx.DeviceCode()
	as.UserCode = ctx.DeviceUserCode()
	if err := ctx.SaveAuthnSession(as); err != nil {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}

	resp := deviceResponse{
		DeviceCode:      as.DeviceCode,
		UserCode:        as.UserCode,
		VerificationURI: ctx.BaseURL() + ctx.DeviceAuthDeviceEndpoint,
		ExpiresIn:       ctx.DeviceAuthLifetimeSecs,
		Interval:        ctx.DeviceAuthPollingIntervalSecs,
	}
	if ctx.DeviceAuthVerificationURICompleteIsEnabled {
		resp.VerificationURIComplete = resp.VerificationURI + "?user_code=" + as.UserCode
	}
	return resp, nil
}

func startDeviceAuth(ctx oidc.Context, userCode string) error {
	// No user code, just render the verification page.
	if userCode == "" {
		return ctx.DeviceAuthPromptUserCode()
	}

	as, err := ctx.AuthnSessionByUserCode(userCode)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return ctx.DeviceAuthPromptUserCode()
		}
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not load the session", err)
	}

	// Delete user code from session to prevent reuse.
	as.UserCode = ""
	if err := ctx.SaveAuthnSession(as); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not save the session", err)
	}

	return authenticate(ctx, as)
}
