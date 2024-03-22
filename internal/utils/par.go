package utils

import (
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func PushAuthorization(ctx Context, req models.PARRequest) error {

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx.CrudManager.ClientManager, models.ClientAuthnContext{
		ClientId:     req.ClientId,
		ClientSecret: req.ClientSecret,
	})
	if err != nil {
		return err
	}

	if err = validatePushedAuthorizationParams(client, req); err != nil {
		return err
	}

	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		Id:          uuid.NewString(),
		RequestUri:  unit.GenerateRequestUri(),
		ClientId:    client.Id,
		Scopes:      strings.Split(req.Scope, " "),
		RedirectUri: req.RedirectUri,
		State:       req.State,
	})
	return nil
}

func validatePushedAuthorizationParams(client models.Client, req models.PARRequest) error {
	if req.RequestUri != "" {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the client must not send a redirect_uri during PAR",
		}
	}

	// The PAR request should accept the same params as the authorize request.
	return validateAuthorizeParams(client, req.ToAuthorizeRequest())
}
