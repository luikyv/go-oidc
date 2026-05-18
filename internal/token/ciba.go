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

// GrantCIBARequest handles the successful resolution of a CIBA request.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token response is sent directly to the client's notification endpoint.
func GrantCIBARequest(ctx oidc.Context, authReqID string) error {
	if _, err := ctx.GrantByAuthReqID(authReqID); err == nil || !errors.Is(err, goidc.ErrNotFound) {
		if err != nil {
			return fmt.Errorf("could not fetch grant: %w", err)
		}
		return errors.New("a grant for the auth_req_id already exists")
	}

	as, err := ctx.CIBASessionByAuthReqID(authReqID)
	if err != nil {
		return err
	}

	if timeutil.TimestampNow() > as.ExpiresAt {
		return DenyCIBARequest(ctx, authReqID, goidc.NewError(goidc.ErrorCodeExpiredToken, "auth_req_id expired"))
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return err
	}

	if !slices.Contains(ctx.CIBATokenDeliveryModes, c.CIBATokenDeliveryMode) {
		return errors.New("client delivery mode is not supported")
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Subject:            as.Subject,
		Username:           as.Username,
		AuthReqID:          as.AuthReqID,
		AuthReqIDExpiresAt: as.ExpiresAt,
		AuthReqIDConsumedAt: func() int {
			if c.CIBATokenDeliveryMode != goidc.CIBADeliveryModePush {
				return 0
			}
			// Push mode completes token delivery during approval, so the auth_req_id
			// must be marked as consumed immediately instead of waiting for a token request.
			return timeutil.TimestampNow()
		}(),
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

	as.Status = goidc.StatusSuccess
	if err := ctx.CIBASaveSession(as); err != nil {
		return fmt.Errorf("could not save authn session: %w", err)
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

// DenyCIBARequest handles denying a CIBA request.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token failure response is sent directly to the client's
//     notification endpoint.
func DenyCIBARequest(ctx oidc.Context, authReqID string, goidcErr goidc.Error) error {
	as, err := ctx.CIBASessionByAuthReqID(authReqID)
	if err != nil {
		return err
	}

	as.Status = goidc.StatusFailure
	if err := ctx.CIBASaveSession(as); err != nil {
		return fmt.Errorf("could not save authn session: %w", err)
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return err
	}

	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePoll {
		return nil
	}

	resp := struct {
		AuthReqID string `json:"auth_req_id,omitempty"`
		goidc.Error
	}{
		AuthReqID: as.AuthReqID,
	}
	if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePing {
		return sendClientNotification(ctx, c, as, resp)
	}

	resp.Error = goidcErr
	return sendClientNotification(ctx, c, as, resp)
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

func generateCIBAToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, fmt.Errorf("invalid client authentication: %w", err)
	}

	if req.authReqID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "auth_req_id is required")
	}

	grant, err := ctx.GrantByAuthReqID(req.authReqID)
	if err != nil {
		if !errors.Is(err, goidc.ErrNotFound) {
			return response{}, fmt.Errorf("could not load ciba grant: %w", err)
		}

		as, sessionErr := ctx.CIBASessionByAuthReqID(req.authReqID)
		if sessionErr != nil {
			if errors.Is(sessionErr, goidc.ErrNotFound) {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", errors.New("no grant or pending CIBA session was found for the auth_req_id"))
			}
			return response{}, sessionErr
		}
		if timeutil.TimestampNow() > as.ExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "auth_req_id expired", errors.New("grant was not found and the pending CIBA session has expired"))
		}
		if as.Status == goidc.StatusPending {
			return response{}, goidc.WrapError(goidc.ErrorCodeAuthPending, "authentication pending", errors.New("grant was not found and the pending CIBA session is still awaiting approval"))
		}
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the authentication session was denied"))
	}

	if grant.RevokedAt != 0 {
		return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "invalid grant", errors.New("grant was revoked"))
	}

	resp, err := func() (response, error) {
		if timeutil.TimestampNow() >= grant.AuthReqIDExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "auth_req_id expired", errors.New("the auth_req_id lifetime has elapsed"))
		}

		if grant.AuthReqIDConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", errors.New("the auth_req_id has already been redeemed"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
			return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the CIBA grant type"))
		}

		if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
			return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client uses push delivery mode and cannot poll the token endpoint"))
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid auth_req_id", errors.New("the auth_req_id belongs to a different client"))
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
		grant.RevokedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return response{}, fmt.Errorf("could not revoke grant: %w", err)
		}
		return response{}, err
	}
	return resp, nil
}
