package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
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

	c, err := ctx.Client(as.ClientID)
	if err != nil {
		return err
	}

	// The client is configured to poll, so no notification is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePoll {
		return nil
	}

	resp := cibaResponse{
		AuthReqID: as.CIBAAuthID,
	}
	// The client is configured to receive a ping, so only the auth request id
	// is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePing {
		return sendClientNotification(ctx, c, as, resp)
	}

	// The client is configured to have the token information pushed, so it won't
	// request the token endpoint later.
	// In that case, the session can be deleted.
	if err := ctx.DeleteAuthnSession(as.ID); err != nil {
		return err
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:                 goidc.GrantCIBA,
		Subject:              as.Subject,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		AuthDetails:          as.GrantedAuthDetails,
		Resources:            as.GrantedResources,
		JWKThumbprint:        as.JWKThumbprint,
		ClientCertThumbprint: as.ClientCertThumbprint,
		Store:                as.Store,
	})
	if err != nil {
		return err
	}

	tkn, tokenValue, err := Issue(ctx, grant, c, nil)
	if err != nil {
		return fmt.Errorf("could not generate access token for the ciba grant: %w", err)
	}

	resp.response = response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		RefreshToken:         grant.RefreshToken,
		Scopes:               tkn.Scopes,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
	}
	if strutil.ContainsOpenID(tkn.Scopes) {
		idTokenOpts := IDTokenOptions{
			Subject: grant.Subject,
			Nonce:   grant.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		}
		if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
			idTokenOpts.AuthReqID = as.PushedAuthReqID
			idTokenOpts.RefreshToken = grant.RefreshToken
		}
		idToken, err := MakeIDToken(ctx, c, idTokenOpts)
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

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return err
	}

	if client.CIBATokenDeliveryMode == goidc.CIBADeliveryModePoll {
		return nil
	}

	resp := struct {
		AuthReqID string `json:"auth_req_id,omitempty"`
		goidc.Error
	}{
		AuthReqID: session.CIBAAuthID,
	}
	if client.CIBATokenDeliveryMode == goidc.CIBADeliveryModePing {
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
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
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

	switch as.Status {
	case goidc.StatusSuccess:
		_ = ctx.DeleteAuthnSession(as.ID)
	case goidc.StatusInProgress:
		return response{}, goidc.NewError(goidc.ErrorCodeAuthPending, "authorization pending")
	default:
		_ = ctx.DeleteAuthnSession(as.ID)
		return response{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "access denied").WithStatusCode(http.StatusBadRequest)
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:                 goidc.GrantCIBA,
		Subject:              as.Subject,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		AuthDetails:          as.GrantedAuthDetails,
		Resources:            as.GrantedResources,
		Store:                as.Store,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	})
	if err != nil {
		return response{}, err
	}

	tkn, tokenValue, err := Issue(ctx, grant, c, &IssuanceOptions{
		Scopes:      req.scopes,
		AuthDetails: req.authDetails,
		Resources:   req.resources,
	})
	if err != nil {
		return response{}, err
	}

	resp := response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		RefreshToken:         grant.RefreshToken,
		Scopes:               tkn.Scopes,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
	}
	if strutil.ContainsOpenID(tkn.Scopes) {
		resp.IDToken, err = MakeIDToken(ctx, c, IDTokenOptions{
			Subject: grant.Subject,
			Nonce:   grant.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
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

	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
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

	if err := validateResources(ctx, as.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, req, c, as.GrantedAuthDetails); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, as); err != nil {
		return err
	}

	return nil
}
