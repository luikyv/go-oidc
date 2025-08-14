package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
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
	session, err := ctx.AuthnSessionByAuthReqID(authReqID)
	if err != nil {
		return err
	}

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return err
	}

	// The client is configured to poll, so no notification is sent.
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePoll {
		return nil
	}

	resp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
	}
	// The client is configured to receive a ping, so only the auth request id
	// is sent.
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePing {
		return sendClientNotification(ctx, client, session, resp)
	}

	// The client is configured to have the token information pushed, so it won't
	// request the token endpoint later.
	// In that case, the session can be deleted.
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return err
	}

	grantInfo, err := cibaPushedGrantInfo(ctx, session)
	if err != nil {
		return err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return fmt.Errorf("could not generate access token for the ciba grant: %w", err)
	}

	tokenResp, err := generateCIBAGrantSession(ctx, client, grantInfo, token, session)
	if err != nil {
		return err
	}

	resp.response = tokenResp
	return sendClientNotification(ctx, client, session, resp)
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

	client, err := ctx.Client(session.ClientID)
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
func sendClientNotification(
	ctx oidc.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
	resp any,
) error {
	body, _ := json.Marshal(resp)
	req, _ := http.NewRequest(http.MethodPost, client.CIBANotificationEndpoint,
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.ClientNotificationToken)

	notificationResp, err := ctx.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = notificationResp.Body.Close() }()

	if !slices.Contains([]int{http.StatusNoContent, http.StatusOK}, notificationResp.StatusCode) {
		return fmt.Errorf("sending notification resulted in status %d", notificationResp.StatusCode)
	}

	return nil
}

func generateCIBAGrant(ctx oidc.Context, req request) (response, error) {
	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	if req.authReqID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "auth_req_id is required")
	}
	session, err := ctx.AuthnSessionByAuthReqID(req.authReqID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", err)
	}

	if err := validateCIBAGrantRequest(ctx, req, client, session); err != nil {
		return response{}, err
	}

	grantInfo, err := cibaGrantInfo(ctx, req, session)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return response{}, fmt.Errorf("could not generate access token for the ciba grant: %w", err)
	}

	return generateCIBAGrantSession(ctx, client, grantInfo, token, session)
}

func cibaPushedGrantInfo(ctx oidc.Context, session *goidc.AuthnSession) (goidc.GrantInfo, error) {

	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantCIBA,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		ActiveScopes:             session.GrantedScopes,
		GrantedScopes:            session.GrantedScopes,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    session.AdditionalTokenClaims,
		JWKThumbprint:            session.JWKThumbprint,
		ClientCertThumbprint:     session.ClientCertThumbprint,
		Store:                    session.Storage,
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthDetails = session.GrantedAuthDetails
		grantInfo.ActiveAuthDetails = session.GrantedAuthDetails
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = session.GrantedResources
		grantInfo.ActiveResources = session.GrantedResources
	}

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}

	return grantInfo, nil
}

func cibaGrantInfo(ctx oidc.Context, req request, session *goidc.AuthnSession) (goidc.GrantInfo, error) {

	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantCIBA,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		ActiveScopes:             session.GrantedScopes,
		GrantedScopes:            session.GrantedScopes,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    session.AdditionalTokenClaims,
		Store:                    session.Storage,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthDetails = session.GrantedAuthDetails
		grantInfo.ActiveAuthDetails = session.GrantedAuthDetails
		if req.authDetails != nil {
			grantInfo.ActiveAuthDetails = req.authDetails
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = session.GrantedResources
		grantInfo.ActiveResources = session.GrantedResources
		if req.resources != nil {
			grantInfo.ActiveResources = req.resources
		}
	}

	setPoP(ctx, &grantInfo)

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}

	return grantInfo, nil
}

func generateCIBAGrantSession(
	ctx oidc.Context,
	client *goidc.Client,
	grantInfo goidc.GrantInfo,
	token Token,
	session *goidc.AuthnSession,
) (
	response,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)

	var refreshTkn string
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		refreshTkn = newRefreshToken()
		grantSession.RefreshToken = refreshTkn
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return response{}, err
	}

	resp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		RefreshToken:         refreshTkn,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}
	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		var err error
		idTokenOpts := newIDTokenOptions(grantInfo)
		if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
			idTokenOpts.AuthReqID = session.PushedAuthReqID
			idTokenOpts.RefreshToken = refreshTkn
		}
		resp.IDToken, err = MakeIDToken(ctx, client, idTokenOpts)
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the ciba grant: %w", err)
		}
	}

	if grantInfo.ActiveScopes != session.Scopes {
		resp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!compareSlices(grantInfo.ActiveResources, session.Resources) {
		resp.Resources = grantInfo.ActiveResources
	}

	return resp, nil
}

func validateCIBAGrantRequest(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
	session *goidc.AuthnSession,
) error {
	if !slices.Contains(client.GrantTypes, goidc.GrantCIBA) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient,
			"the client is not authorized as it is configured in push mode")
	}

	if client.ID != session.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"the authorization request id was not issued to the client")
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeExpiredToken,
			"the authorization request id is expired")
	}

	if err := ValidateBinding(ctx, client, nil); err != nil {
		return err
	}

	if err := validateBackAuth(ctx, session); err != nil {
		return err
	}

	if err := validateResources(ctx, session.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, session.GrantedAuthDetails, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, session); err != nil {
		return err
	}

	return nil
}

// validateBackAuth checks whether an authentication session is ready
// to generate a grant session for CIBA.
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
