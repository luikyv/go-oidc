package dcr

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func create(
	ctx oidc.Context,
	initialToken string,
	meta *goidc.ClientMetaInfo,
) (
	response,
	error,
) {

	if err := ctx.ValidateInitalAccessToken(initialToken); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied,
			"invalid token", err)
	}

	if err := validate(ctx, meta); err != nil {
		return response{}, err
	}

	if err := ctx.HandleDynamicClient(meta); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata,
			"invalid metadata", err)
	}

	if err := validate(ctx, meta); err != nil {
		return response{}, err
	}

	client := &goidc.Client{
		ClientMetaInfo: *meta,
	}
	return modifyAndSaveClient(ctx, client)
}

func update(
	ctx oidc.Context,
	id string,
	regToken string,
	meta *goidc.ClientMetaInfo,
) (
	response,
	error,
) {
	client, err := protected(ctx, id, regToken)
	if err != nil {
		return response{}, err
	}

	if err := validate(ctx, meta); err != nil {
		return response{}, err
	}

	if err := ctx.HandleDynamicClient(meta); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata,
			"invalid metadata", err)
	}

	if err := validate(ctx, meta); err != nil {
		return response{}, err
	}

	client.ClientMetaInfo = *meta
	return modifyAndSaveClient(ctx, client)
}

func fetch(
	ctx oidc.Context,
	id string,
	regToken string,
) (
	response,
	error,
) {

	client, err := protected(ctx, id, regToken)
	if err != nil {
		return response{}, err
	}

	return response{
		ID:              client.ID,
		RegistrationURI: registrationURI(ctx, client.ID),
		ClientMetaInfo:  &client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx oidc.Context,
	id string,
	regToken string,
) error {
	_, err := protected(ctx, id, regToken)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(id); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not delete the client", err)
	}
	return nil
}

func modifyAndSaveClient(
	ctx oidc.Context,
	client *goidc.Client,
) (
	response,
	error,
) {

	id := setID(ctx, client)
	regToken := setRegistrationToken(ctx, client)
	secret := setSecret(ctx, client)

	if err := ctx.SaveClient(client); err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not store the client", err)
	}

	return response{
		ID:                id,
		RegistrationURI:   registrationURI(ctx, id),
		RegistrationToken: regToken,
		Secret:            secret,
		ClientMetaInfo:    &client.ClientMetaInfo,
	}, nil
}

// setID assigns a unique ID to the client if it doesn't already have one.
// If the client already has an ID, it returns the existing ID.
// Otherwise, it generates a new ID and returns it.
func setID(_ oidc.Context, client *goidc.Client) string {
	if client.ID == "" {
		client.ID = clientID()
	}
	return client.ID
}

// setRegistrationToken generates and assigns a new registration token for the
// client if one doesn't already exist or if token rotation is enabled.
// The function returns the plain registration token, or an empty string if no
// new token is generated.
func setRegistrationToken(ctx oidc.Context, client *goidc.Client) string {
	// Generate a new registration token only if the client does not have one
	// or if token rotation is enabled.
	if client.HashedRegistrationAccessToken != "" && !ctx.DCRTokenRotationIsEnabled {
		return ""
	}

	regToken, hashedRegToken := registrationAccessTokenAndHash()
	client.HashedRegistrationAccessToken = hashedRegToken
	return regToken
}

// setSecret configures the client's secret based on its authentication methods.
// It supports two types of secret-based authentication:
//  1. Basic/Post: The secret is stored as a hashed value.
//  2. JWT: The secret is stored as plain text.
//
// If a new secret is generated, it returns the plain secret; otherwise, it
// returns an empty string.
func setSecret(ctx oidc.Context, client *goidc.Client) string {
	var secret string
	// Clear the client's secret and hashed secret to ensure it's only set when
	// secret-based authentication is required.
	client.Secret = ""
	client.HashedSecret = ""
	authnMethods := authnMethods(ctx, &client.ClientMetaInfo)

	// Check for client authentication methods that require a secret that must
	// be store as a hash.
	if slices.ContainsFunc(authnMethods, func(method goidc.ClientAuthnType) bool {
		return method == goidc.ClientAuthnSecretBasic || method == goidc.ClientAuthnSecretPost
	}) {
		secret, client.HashedSecret = clientSecretAndHash()
	}

	// Check for client authentication using secret JWT.
	if slices.ContainsFunc(authnMethods, func(method goidc.ClientAuthnType) bool {
		return method == goidc.ClientAuthnSecretJWT
	}) {
		// Use existing secret or generate a new one if not already set.
		if secret == "" {
			secret = clientSecret()
		}
		client.Secret = secret
	}

	return secret
}

func authnMethods(ctx oidc.Context, meta *goidc.ClientMetaInfo) []goidc.ClientAuthnType {
	authnMethods := []goidc.ClientAuthnType{meta.TokenAuthnMethod}
	if ctx.TokenIntrospectionIsEnabled {
		authnMethods = append(authnMethods, meta.TokenIntrospectionAuthnMethod)
	}
	if ctx.TokenRevocationIsEnabled {
		authnMethods = append(authnMethods, meta.TokenRevocationAuthnMethod)
	}
	return authnMethods
}

func registrationURI(ctx oidc.Context, id string) string {
	return ctx.BaseURL() + ctx.EndpointDCR + "/" + id
}

// protected returns a client corresponding to the id informed if the
// the registration access token is valid.
func protected(
	ctx oidc.Context,
	id string,
	regToken string,
) (
	*goidc.Client,
	error,
) {
	c, err := ctx.Client(id)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not find the client", err)
	}

	if !isRegistrationAccessTokenValid(c, regToken) {
		return nil, goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid access token")
	}

	return c, nil
}

func clientID() string {
	return "dc-" + strutil.Random(idLength)
}

func clientSecretAndHash() (string, string) {
	secret := clientSecret()
	hashedSecret := strutil.BCryptHash(secret)
	return secret, hashedSecret
}

func clientSecret() string {
	return strutil.Random(secretLength)
}

func registrationAccessTokenAndHash() (string, string) {
	token := strutil.Random(registrationAccessTokenLength)
	hashedToken := strutil.BCryptHash(token)
	return token, hashedToken
}

func isRegistrationAccessTokenValid(c *goidc.Client, token string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(c.HashedRegistrationAccessToken),
		[]byte(token),
	)
	return err == nil
}
