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
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// NotifyCIBAGrant handles notifying a client that the user has granted access.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token response is sent directly to the client's notification endpoint.
func NotifyCIBAGrant(ctx oidc.Context, authReqID string) error {
	as, err := ctx.CIBASession(authReqID)
	if err != nil {
		return err
	}

	if err := ctx.CIBADeleteSession(as.ID); err != nil {
		return err
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return err
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Subject:              as.Subject,
		Username:             as.Username,
		CIBAID:               authReqID,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		AuthDetails:          as.GrantedAuthDetails,
		Resources:            as.GrantedResources,
		JWKThumbprint:        as.JWKThumbprint,
		ClientCertThumbprint: as.ClientCertThumbprint,
		AuthParams:           as.AuthorizationParameters,
		Store:                as.Store,
	})
	if err != nil {
		return err
	}

	// The client is configured to poll, so no notification is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePoll {
		return nil
	}

	resp := cibaResponse{
		AuthReqID: grant.AuthReqID,
	}
	// The client is configured to receive a ping, so only the auth request id is sent.
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePing {
		return sendClientNotification(ctx, c, as, resp)
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
			Nonce:   grant.AuthParams.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		}
		if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
			idTokenOpts.AuthReqID = grant.AuthReqID
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
	as, err := ctx.CIBASession(authReqID)
	if err != nil {
		return err
	}

	client, err := client.Client(ctx, as.ClientID)
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
		AuthReqID: as.ID,
	}
	if client.CIBATokenDeliveryMode == goidc.CIBADeliveryModePing {
		return sendClientNotification(ctx, client, as, resp)
	}

	if err := ctx.CIBADeleteSession(as.ID); err != nil {
		return err
	}

	resp.Error = goidcErr
	return sendClientNotification(ctx, client, as, resp)
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

func generateCIBAGrantToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	if req.authReqID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "auth_req_id is required")
	}

	grant, err := ctx.GrantByAuthReqID(req.authReqID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", err)
	}

	resp, err := func() (response, error) {
		if grant.AuthReqIDConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", err)
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
			return response{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
		}

		if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
			return response{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the client is not authorized as it is configured in push mode")
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization request id was not issued to the client")
		}

		if err := ValidateBinding(ctx, c, nil); err != nil {
			return response{}, err
		}

		if err := validateResources(ctx, req, grant.Resources); err != nil {
			return response{}, err
		}

		if err := validateAuthDetails(ctx, req, c, grant.AuthDetails); err != nil {
			return response{}, err
		}

		if err := validateScopes(ctx, req, c, grant.Scopes); err != nil {
			return response{}, err
		}

		grant.JWKThumbprint = dpopThumbprint(ctx)
		grant.CertThumbprint = tlsThumbprint(ctx)
		grant.AuthReqIDConsumedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
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
				Nonce:   grant.AuthParams.Nonce,
				Claims:  ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return response{}, fmt.Errorf("could not generate id token for the ciba grant: %w", err)
			}
		}

		return resp, nil
	}()
	if err != nil {
		_ = ctx.DeleteGrant(grant.ID)
		return response{}, err
	}
	return resp, nil
}
