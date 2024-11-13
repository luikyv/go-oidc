package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func NotifyCIBAGrant(
	ctx oidc.Context,
	authReqID string,
) error {
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

	type cibaResponse struct {
		AuthReqID string `json:"auth_req_id,omitempty"`
		response
	}
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePing {
		return sendClientNotification(ctx, client, session, cibaResponse{
			AuthReqID: session.CIBAAuthID,
		})
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return err
	}

	grantInfo, err := cibaPushedGrantInfo(ctx, session)
	if err != nil {
		return err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not generate access token for the ciba grant", err)
	}

	grantSession, err := generateCIBAGrantSession(ctx, client, grantInfo, token)
	if err != nil {
		return err
	}

	resp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		response: response{
			AccessToken:          token.Value,
			ExpiresIn:            token.LifetimeSecs,
			TokenType:            token.Type,
			RefreshToken:         grantSession.RefreshToken,
			AuthorizationDetails: grantInfo.ActiveAuthDetails,
		},
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		idTokenOpts := newIDTokenOptions(grantInfo)
		idTokenOpts.AuthReqID = session.PushedAuthReqID
		idTokenOpts.RefreshToken = grantSession.RefreshToken
		resp.IDToken, err = MakeIDToken(ctx, client, idTokenOpts)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInternalError,
				"could not generate id token for the ciba grant", err)
		}
	}

	if grantInfo.ActiveScopes != session.Scopes {
		resp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!cmp.Equal(grantInfo.ActiveResources, session.Resources) {
		resp.Resources = grantInfo.ActiveResources
	}

	return sendClientNotification(ctx, client, session, resp)
}

func NotifyCIBAGrantFailure(
	ctx oidc.Context,
	authReqID string,
	goidcErr goidc.Error,
) error {
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

	type cibaErrorResponse struct {
		AuthReqID string `json:"auth_req_id,omitempty"`
		goidc.Error
	}
	if client.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePing {
		return sendClientNotification(ctx, client, session, cibaErrorResponse{
			AuthReqID: session.CIBAAuthID,
		})
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return err
	}

	return sendClientNotification(ctx, client, session, cibaErrorResponse{
		AuthReqID: session.CIBAAuthID,
		Error:     goidcErr,
	})
}

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
	defer notificationResp.Body.Close()

	if !slices.Contains([]int{http.StatusNoContent, http.StatusOK}, notificationResp.StatusCode) {
		return fmt.Errorf("sending notification resulted in status %d", notificationResp.StatusCode)
	}

	return nil
}

func generateCIBAGrant(
	ctx oidc.Context,
	req request,
) (
	response,
	error,
) {
	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	if req.authReqID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"authorization request id is required")
	}
	session, err := ctx.AuthnSessionByAuthReqID(req.authReqID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant,
			"invalid auth_req_id", err)
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
		return response{}, goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not generate access token for the ciba grant", err)
	}

	grantSession, err := generateCIBAGrantSession(ctx, client, grantInfo, token)
	if err != nil {
		return response{}, err
	}

	resp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		RefreshToken:         grantSession.RefreshToken,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		resp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, goidc.WrapError(goidc.ErrorCodeInternalError,
				"could not generate id token for the ciba grant", err)
		}
	}

	if grantInfo.ActiveScopes != session.Scopes {
		resp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!cmp.Equal(grantInfo.ActiveResources, session.Resources) {
		resp.Resources = grantInfo.ActiveResources
	}

	return resp, nil
}

// TODO: Find a way to bind the token.
func cibaPushedGrantInfo(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) (
	goidc.GrantInfo,
	error,
) {

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

func cibaGrantInfo(
	ctx oidc.Context,
	req request,
	session *goidc.AuthnSession,
) (
	goidc.GrantInfo,
	error,
) {

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
) (
	*goidc.GrantSession,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		grantSession.RefreshToken = refreshToken()
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, err
	}

	return grantSession, nil
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
