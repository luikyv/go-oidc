package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// NotifyCIBAGrant handles notifying a client that the user has granted access.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token response is sent directly to the client's notification endpoint.
func NotifyCIBAGrant(ctx oidc.Context, authReqID string) error {
	as, err := ctx.AuthnSessionByAuthReqID(authReqID)
	if err != nil {
		return err
	}

	c, err := client.Client(ctx,as.ClientID)
	if err != nil {
		return err
	}

	// The client is configured to poll, so no notification is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePoll {
		return nil
	}

	resp := cibaResponse{
		AuthReqID: as.CIBAAuthID,
	}
	// The client is configured to receive a ping, so only the auth request id
	// is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePing {
		return sendClientNotification(ctx, c, as, resp)
	}

	// The client is configured to have the token information pushed, so it won't
	// request the token endpoint later.
	// In that case, the session can be deleted.
	if err := ctx.DeleteAuthnSession(as.ID); err != nil {
		return err
	}

	// Build grant for push mode.
	grant := &goidc.Grant{
		ID:                   ctx.GrantID(),
		CreatedAtTimestamp:   timeutil.TimestampNow(),
		Type:                 goidc.GrantCIBA,
		Subject:              as.Subject,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		JWKThumbprint:        as.JWKThumbprint,
		ClientCertThumbprint: as.ClientCertThumbprint,
		Store:                as.Storage,
		AuthDetails: func() []goidc.AuthorizationDetail {
			if ctx.AuthDetailsIsEnabled {
				return as.GrantedAuthDetails
			}
			return nil
		}(),
		Resources: func() goidc.Resources {
			if ctx.ResourceIndicatorsIsEnabled {
				return as.GrantedResources
			}
			return nil
		}(),
	}

	if err := ctx.HandleGrant(grant); err != nil {
		return err
	}

	opts := ctx.TokenOptions(grant, c)
	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID: func() string {
			if opts.Format == goidc.TokenFormatJWT {
				return ctx.JWTID()
			}
			return ctx.OpaqueToken()
		}(),
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		AuthDetails:          grant.AuthDetails,
		Resources:            grant.Resources,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + opts.LifetimeSecs,
		Format:               opts.Format,
		SigAlg:               opts.JWTSigAlg,
	}

	tokenValue, err := Make(ctx, tkn, grant)
	if err != nil {
		return fmt.Errorf("could not generate access token for the ciba grant: %w", err)
	}

	if shouldIssueRefreshToken(ctx, c, grant) {
		grant.RefreshToken = ctx.RefreshToken()
	}

	if err := ctx.SaveGrant(grant); err != nil {
		return err
	}

	if err := ctx.SaveToken(tkn); err != nil {
		return err
	}

	resp.response = response{
		AccessToken:  tokenValue,
		ExpiresIn:    tkn.LifetimeSecs(),
		TokenType:    tokenType(tkn),
		RefreshToken: grant.RefreshToken,
		Scopes: func() string {
			if tkn.Scopes == as.GrantedScopes {
				return ""
			}
			return tkn.Scopes
		}(),
		AuthorizationDetails: tkn.AuthDetails,
		Resources: func() goidc.Resources {
			if !ctx.ResourceIndicatorsIsEnabled || compareSlices(tkn.Resources, as.GrantedResources) {
				return nil
			}
			return tkn.Resources
		}(),
	}
	if strutil.ContainsOpenID(tkn.Scopes) {
		idTokenOpts := newIDTokenOptions(grant)
		if c.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
			idTokenOpts.AuthReqID = as.PushedAuthReqID
			idTokenOpts.RefreshToken = grant.RefreshToken
		}
		idToken, err := MakeIDToken(ctx, c, grant, idTokenOpts)
		if err != nil {
			return fmt.Errorf("could not generate id token for the ciba grant: %w", err)
		}
		resp.IDToken = idToken
	}

	return sendClientNotification(ctx, c, as, resp)
}

// NotifyCIBAGrantFailure handles notifying a client that the user has denied access.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token failure response is sent directly to the client's
//     notification endpoint.
func NotifyCIBAGrantFailure(ctx oidc.Context, authReqID string, goidcErr goidc.Error) error {
	session, err := ctx.AuthnSessionByAuthReqID(authReqID)
	if err != nil {
		return err
	}

	client, err := client.Client(ctx,session.ClientID)
	if err != nil {
		return err
	}

	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePoll {
		return nil
	}

	resp := struct {
		AuthReqID string `json:"auth_req_id,omitempty"`
		goidc.Error
	}{
		AuthReqID: session.CIBAAuthID,
	}
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePing {
		return sendClientNotification(ctx, client, session, resp)
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return err
	}

	resp.Error = goidcErr
	return sendClientNotification(ctx, client, session, resp)
}

// sendClientNotification sends a payload to the client notification endpoint.
func sendClientNotification(ctx oidc.Context, client *goidc.Client, session *goidc.AuthnSession, resp any) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("could not marshal response: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, client.CIBANotificationEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.ClientNotificationToken)

	notificationResp, err := ctx.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer notificationResp.Body.Close() //nolint:errcheck

	if !slices.Contains([]int{http.StatusNoContent, http.StatusOK}, notificationResp.StatusCode) {
		return fmt.Errorf("sending notification resulted in status %d", notificationResp.StatusCode)
	}

	return nil
}

func generateCIBAGrant(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	if req.authReqID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "auth_req_id is required")
	}
	as, err := ctx.AuthnSessionByAuthReqID(req.authReqID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", err)
	}

	if err := validateCIBAGrantRequest(ctx, req, c, as); err != nil {
		return response{}, err
	}

	grant := &goidc.Grant{
		ID:                 ctx.GrantID(),
		CreatedAtTimestamp: timeutil.TimestampNow(),
		Type:               goidc.GrantCIBA,
		Subject:            as.Subject,
		ClientID:           as.ClientID,
		Scopes:             as.GrantedScopes,
		Store:              as.Storage,
		AuthDetails: func() []goidc.AuthorizationDetail {
			if ctx.AuthDetailsIsEnabled {
				return as.GrantedAuthDetails
			}
			return nil
		}(),
		Resources: func() goidc.Resources {
			if ctx.ResourceIndicatorsIsEnabled {
				return as.GrantedResources
			}
			return nil
		}(),
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}
	if shouldIssueRefreshToken(ctx, c, grant) {
		grant.RefreshToken = ctx.RefreshToken()
	}

	if err := ctx.HandleGrant(grant); err != nil {
		return response{}, err
	}

	opts := ctx.TokenOptions(grant, c)
	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID: func() string {
			if opts.Format == goidc.TokenFormatJWT {
				return ctx.JWTID()
			}
			return ctx.OpaqueToken()
		}(),
		GrantID:  grant.ID,
		Subject:  grant.Subject,
		ClientID: grant.ClientID,
		Scopes: func() string {
			if req.scopes != "" {
				return req.scopes
			}
			return grant.Scopes
		}(),
		AuthDetails: func() []goidc.AuthorizationDetail {
			if ctx.AuthDetailsIsEnabled && req.authDetails != nil {
				return req.authDetails
			}
			return grant.AuthDetails
		}(),
		Resources: func() goidc.Resources {
			if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
				return req.resources
			}
			return grant.Resources
		}(),
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + opts.LifetimeSecs,
		Format:               opts.Format,
		SigAlg:               opts.JWTSigAlg,
	}

	tokenValue, err := Make(ctx, tkn, grant)
	if err != nil {
		return response{}, fmt.Errorf("could not generate access token for the ciba grant: %w", err)
	}

	if err := ctx.SaveGrant(grant); err != nil {
		return response{}, err
	}

	if err := ctx.SaveToken(tkn); err != nil {
		return response{}, err
	}

	resp := response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tokenType(tkn),
		RefreshToken:         grant.RefreshToken,
		AuthorizationDetails: tkn.AuthDetails,
		Scopes: func() string {
			if tkn.Scopes == as.GrantedScopes {
				return ""
			}
			return tkn.Scopes
		}(),
		Resources: func() goidc.Resources {
			if !ctx.ResourceIndicatorsIsEnabled || compareSlices(tkn.Resources, as.GrantedResources) {
				return nil
			}
			return tkn.Resources
		}(),
	}
	if strutil.ContainsOpenID(tkn.Scopes) {
		var err error
		idTokenOpts := newIDTokenOptions(grant)
		resp.IDToken, err = MakeIDToken(ctx, c, grant, idTokenOpts)
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the ciba grant: %w", err)
		}
	}

	return resp, nil
}

func validateCIBAGrantRequest(ctx oidc.Context, req request, c *goidc.Client, as *goidc.AuthnSession) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the client is not authorized as it is configured in push mode")
	}

	if c.ID != as.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization request id was not issued to the client")
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeExpiredToken, "the authorization request id is expired")
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return err
	}

	if err := validateBackAuth(ctx, as); err != nil {
		return err
	}

	if err := validateResources(ctx, as.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, as.GrantedAuthDetails, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, as); err != nil {
		return err
	}

	return nil
}

// validateBackAuth checks whether an authentication session is ready
// to generate a grant for CIBA.
func validateBackAuth(ctx oidc.Context, session *goidc.AuthnSession) error {
	validationErr := ctx.ValidateBackAuth(session)
	if validationErr == nil {
		// If validation succeeds, delete the session to prevent reuse.
		return ctx.DeleteAuthnSession(session.ID)
	}

	// If validation fails with either an authorization_pending or slow_down error
	// (indicating the client should retry later), return the specific error
	// without further processing.
	var goidcErr goidc.Error
	if errors.As(validationErr, &goidcErr) && slices.Contains(
		[]goidc.ErrorCode{goidc.ErrorCodeAuthPending, goidc.ErrorCodeSlowDown},
		goidcErr.Code,
	) {
		return validationErr
	}

	// If validation fails for other reasons, delete the session to prevent reuse
	// and return the validation error.
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return err
	}
	return validationErr
}
