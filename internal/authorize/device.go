package authorize

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
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
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the device_code grant type"))
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(req.Scopes) {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "scope openid is required", errors.New("scope openid is required"))
	}

	if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, c); err != nil {
		return deviceResponse{}, err
	}

	as := newAuthnSession(ctx, req.AuthorizationParameters, c)
	policy, ok := ctx.AvailablePolicy(as, c)
	if !ok {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("no authentication policy is available for the device request"))
	}

	as.ExpiresAt = as.CreatedAt + ctx.DeviceAuthLifetimeSecs
	as.PolicyID = policy.ID
	as.DeviceCode = ctx.DeviceCode()
	as.UserCode = ctx.DeviceUserCode()
	if err := ctx.DeviceSaveSession(as); err != nil {
		return deviceResponse{}, fmt.Errorf("could not save the device session: %w", err)
	}

	resp := deviceResponse{
		DeviceCode:      as.DeviceCode,
		UserCode:        as.UserCode,
		VerificationURI: ctx.BaseURL() + ctx.DeviceAuthVerificationEndpoint,
		ExpiresIn:       ctx.DeviceAuthLifetimeSecs,
		Interval:        ctx.DeviceAuthPollingIntervalSecs,
	}
	if ctx.DeviceAuthVerificationURICompleteIsEnabled {
		resp.VerificationURIComplete = resp.VerificationURI + "?user_code=" + as.UserCode
	}
	return resp, nil
}

func initDeviceAuthVerification(ctx oidc.Context, userCode string) error {
	// No user code, just render the verification page.
	if userCode == "" {
		return ctx.DeviceAuthPromptUserCode()
	}

	as, err := ctx.DeviceSessionByUserCode(userCode)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return ctx.DeviceAuthPromptUserCode()
		}
		return fmt.Errorf("could not load the device session by user code: %w", err)
	}
	return authenticateDevice(ctx, as)
}

func continueDeviceAuthVerification(ctx oidc.Context, id string) error {
	as, err := ctx.DeviceSession(id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the device authentication session was not found"))
		}
		return fmt.Errorf("could not load the device session by id: %w", err)
	}

	return authenticateDevice(ctx, as)
}

func authenticateDevice(ctx oidc.Context, as *goidc.AuthnSession) error {
	// If the policy ID is missing, the callback endpoint was accessed without
	// first going through the device endpoint. This indicates an invalid
	// or incomplete device flow, so the session must be deleted and an
	// error returned.
	if as.PolicyID == "" {
		as.Status = goidc.StatusFailure
		if err := ctx.DeviceSaveSession(as); err != nil {
			return fmt.Errorf("could not save the failed device session with a missing policy id: %w", err)
		}
		return fmt.Errorf("the device session is missing the policy id")
	}

	if timeutil.TimestampNow() >= as.ExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the device authentication session has expired"))
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return fmt.Errorf("could not load the client for the device session: %w", err)
	}

	switch status, authErr := ctx.Policy(as.PolicyID).Authenticate(ctx.Response, ctx.Request, as, c); status {
	case goidc.StatusSuccess:
		as.Status = goidc.StatusSuccess
		if err := ctx.DeviceSaveSession(as); err != nil {
			return fmt.Errorf("could not save the device session: %w", err)
		}

		_, err = token.NewGrant(ctx, c, token.GrantOptions{
			Subject:             as.Subject,
			Username:            as.Username,
			ClientID:            as.ClientID,
			Scopes:              as.GrantedScopes,
			Nonce:               as.Nonce,
			AuthDetails:         as.GrantedAuthDetails,
			Resources:           as.GrantedResources,
			DeviceCode:          as.DeviceCode,
			DeviceCodeExpiresAt: as.ExpiresAt,
			AuthParams:          as.AuthorizationParameters,
			Store:               as.Store,
		})
		if err != nil {
			return fmt.Errorf("could not generate the grant for the device session: %w", err)
		}

		return ctx.DeviceAuthRenderConfirmation()
	case goidc.StatusPending:
		as.Status = goidc.StatusPending
		if err := ctx.DeviceSaveSession(as); err != nil {
			return fmt.Errorf("could not save the pending device session: %w", err)
		}
		return nil
	default:
		as.Status = goidc.StatusFailure
		if err := ctx.DeviceSaveSession(as); err != nil {
			return fmt.Errorf("could not save the failed device session: %w", err)
		}

		var oidcErr goidc.Error
		if errors.As(authErr, &oidcErr) {
			return oidcErr
		}

		if authErr != nil {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", authErr)
		}

		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("authentication policy failed"))
	}
}
