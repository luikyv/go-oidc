package authorize

import (
	"errors"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
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
	policy, ok := ctx.AvailablePolicy(as, c)
	if !ok {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "no policy available")
	}

	as.ExpiresAt = as.CreatedAt + ctx.DeviceAuthLifetimeSecs
	as.PolicyID = policy.ID
	as.DeviceCode = ctx.DeviceCode()
	as.UserCode = ctx.DeviceUserCode()
	if err := ctx.DeviceSaveSession(as); err != nil {
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

	as, err := ctx.DeviceSessionByUserCode(userCode)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return ctx.DeviceAuthPromptUserCode()
		}
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not load the session", err)
	}

	return authenticateDevice(ctx, as)
}

func continueDeviceAuth(ctx oidc.Context, id string) error {
	as, err := ctx.DeviceSession(id)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not load the session", err)
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	return authenticateDevice(ctx, as)
}

func authenticateDevice(ctx oidc.Context, as *goidc.AuthnSession) error {
	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError, "could not load client", err)
	}

	switch status, authErr := ctx.Policy(as.PolicyID).Authenticate(ctx.Response, ctx.Request, as, c); status {
	case goidc.StatusSuccess:
		if err := ctx.DeviceDeleteSession(as.ID); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "could not save session", err)
		}

		_, err = token.NewGrant(ctx, c, token.GrantOptions{
			Subject:     as.Subject,
			Username:    as.Username,
			ClientID:    as.ClientID,
			Scopes:      as.GrantedScopes,
			Nonce:       as.Nonce,
			AuthDetails: as.GrantedAuthDetails,
			Resources:   as.GrantedResources,
			DeviceCode:  as.DeviceCode,
			AuthParams:  as.AuthorizationParameters,
			Store:       as.Store,
		})
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "could not generate the grant", err)
		}

		return ctx.DeviceAuthRenderConfirmation()
	case goidc.StatusInProgress:
		return ctx.AuthSaveSession(as)
	default:
		if err := ctx.AuthDeleteSession(as.ID); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", err)
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
