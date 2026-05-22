package dcr

import (
	"crypto/subtle"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func create(ctx oidc.Context, initialToken string, req *client.Meta) (response, error) {
	if err := ctx.ValidateInitalAccessToken(initialToken); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "invalid token", err)
	}

	if err := client.Resolve(ctx, req); err != nil {
		return response{}, err
	}

	id := ctx.ClientID()
	if err := ctx.HandleDynamicClient(id, &req.ClientMeta); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid metadata", err)
	}

	c := &goidc.Client{
		ID:                id,
		CreatedAt:         timeutil.TimestampNow(),
		RegistrationToken: ctx.RegistrationAccessToken(),
		ClientMeta:        req.ClientMeta,
	}

	var secret string
	var secretExpiresAt *int
	if c.TokenAuthnMethod == goidc.AuthnMethodSecretBasic || c.TokenAuthnMethod == goidc.AuthnMethodSecretPost || c.TokenAuthnMethod == goidc.AuthnMethodSecretJWT {
		secret = ctx.ClientSecret()
		c.Secret = secret

		var exp int
		if ctx.DCRSecretLifetimeSecs != 0 {
			exp = timeutil.TimestampNow() + ctx.DCRSecretLifetimeSecs
		}
		secretExpiresAt = &exp
		c.SecretExpiresAt = exp
	}

	if err := ctx.DCRSaveClient(c); err != nil {
		return response{}, err
	}

	return response{
		ID:                c.ID,
		RegistrationURI:   ctx.BaseURL() + ctx.DCREndpoint + "/" + c.ID,
		RegistrationToken: c.RegistrationToken,
		Secret:            c.Secret,
		SecretExpiresAt:   secretExpiresAt,
		ClientMeta:        &c.ClientMeta,
	}, nil
}

func update(ctx oidc.Context, id, tkn string, req *client.Meta) (response, error) {
	c, err := protected(ctx, id, tkn)
	if err != nil {
		return response{}, err
	}

	if err := client.Resolve(ctx, req); err != nil {
		return response{}, err
	}

	if err := ctx.HandleDynamicClient(id, &req.ClientMeta); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid metadata", err)
	}

	c.ClientMeta = req.ClientMeta

	var regToken string
	if ctx.DCRTokenRotationIsEnabled {
		regToken = ctx.RegistrationAccessToken()
		c.RegistrationToken = regToken
	}

	var secret string
	var secretExpiresAt *int
	if c.TokenAuthnMethod == goidc.AuthnMethodSecretBasic || c.TokenAuthnMethod == goidc.AuthnMethodSecretPost || c.TokenAuthnMethod == goidc.AuthnMethodSecretJWT {
		if c.Secret == "" || ctx.DCRSecretRotationIsEnabled {
			secret = ctx.ClientSecret()
			c.Secret = secret

			var exp int
			if ctx.DCRSecretLifetimeSecs != 0 {
				exp = timeutil.TimestampNow() + ctx.DCRSecretLifetimeSecs
			}
			secretExpiresAt = &exp
			c.SecretExpiresAt = exp
		}
	} else {
		// Clear the client's secret to ensure it's only set when
		// secret-based authentication is required.
		c.Secret = ""
		c.SecretExpiresAt = 0
	}

	if err := ctx.DCRSaveClient(c); err != nil {
		return response{}, err
	}

	return response{
		ID:                c.ID,
		RegistrationURI:   ctx.BaseURL() + ctx.DCREndpoint + "/" + c.ID,
		RegistrationToken: regToken,
		Secret:            secret,
		SecretExpiresAt:   secretExpiresAt,
		ClientMeta:        &c.ClientMeta,
	}, nil
}

func fetch(ctx oidc.Context, id, tkn string) (response, error) {
	c, err := protected(ctx, id, tkn)
	if err != nil {
		return response{}, err
	}

	var regToken string
	if ctx.DCRTokenRotationIsEnabled {
		regToken = ctx.RegistrationAccessToken()
		c.RegistrationToken = regToken
	}

	var secret string
	var secretExpiresAt *int
	if (c.TokenAuthnMethod == goidc.AuthnMethodSecretBasic || c.TokenAuthnMethod == goidc.AuthnMethodSecretPost || c.TokenAuthnMethod == goidc.AuthnMethodSecretJWT) && ctx.DCRSecretRotationIsEnabled {
		secret = ctx.ClientSecret()
		c.Secret = secret

		var exp int
		if ctx.DCRSecretLifetimeSecs != 0 {
			exp = timeutil.TimestampNow() + ctx.DCRSecretLifetimeSecs
		}
		secretExpiresAt = &exp
		c.SecretExpiresAt = exp
	}

	if secret != "" || regToken != "" {
		if err := ctx.DCRSaveClient(c); err != nil {
			return response{}, err
		}
	}

	return response{
		ID:                c.ID,
		RegistrationURI:   ctx.BaseURL() + ctx.DCREndpoint + "/" + c.ID,
		RegistrationToken: regToken,
		Secret:            secret,
		SecretExpiresAt:   secretExpiresAt,
		ClientMeta:        &c.ClientMeta,
	}, nil
}

func remove(ctx oidc.Context, id, regToken string) error {
	if _, err := protected(ctx, id, regToken); err != nil {
		return err
	}

	return ctx.DCRDeleteClient(id)
}

// protected returns a client corresponding to the id informed if the
// the registration access token is valid.
func protected(ctx oidc.Context, id, regToken string) (*goidc.Client, error) {
	c, err := ctx.DCRClient(id)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not find the client", err)
	}

	if subtle.ConstantTimeCompare([]byte(regToken), []byte(c.RegistrationToken)) != 1 {
		return nil, goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid access token")
	}

	return c, nil
}
