package dcr

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func create(
	ctx *oidc.Context,
	dc request,
) (
	response,
	error,
) {
	if err := setCreationDefaults(ctx, &dc); err != nil {
		return response{}, err
	}

	if err := validateDynamicRequest(ctx, dc); err != nil {
		return response{}, err
	}

	if err := ctx.ExecuteDCRPlugin(&dc.ClientMetaInfo); err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidClientMetadata,
			"invalid metadata", err)
	}

	if err := validateDynamicRequest(ctx, dc); err != nil {
		return response{}, err
	}

	newClient := newClient(dc)
	if err := ctx.SaveClient(newClient); err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not store the client", err)
	}

	return response{
		ID:                dc.id,
		RegistrationURI:   registrationURI(ctx, dc.id),
		RegistrationToken: dc.registrationToken,
		Secret:            dc.secret,
		ClientMetaInfo:    dc.ClientMetaInfo,
	}, nil
}

func setCreationDefaults(
	ctx *oidc.Context,
	req *request,
) error {
	id, err := clientID()
	if err != nil {
		return err
	}
	req.id = id

	token, err := registrationAccessToken()
	if err != nil {
		return err
	}
	req.registrationToken = token

	return setDefaults(ctx, req)
}

func update(
	ctx *oidc.Context,
	dc request,
) (
	response,
	error,
) {
	c, err := protected(ctx, dc)
	if err != nil {
		return response{}, err
	}

	if err := setUpdateDefaults(ctx, c, &dc); err != nil {
		return response{}, err
	}

	if err := validateDynamicRequest(ctx, dc); err != nil {
		return response{}, err
	}

	if err := ctx.ExecuteDCRPlugin(&dc.ClientMetaInfo); err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidClientMetadata,
			"invalid metadata", err)
	}

	if err := validateDynamicRequest(ctx, dc); err != nil {
		return response{}, err
	}

	updatedClient := newClient(dc)
	if err := ctx.SaveClient(updatedClient); err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not store the client", err)
	}

	resp := response{
		ID:              dc.id,
		RegistrationURI: registrationURI(ctx, dc.id),
		Secret:          dc.secret,
		ClientMetaInfo:  dc.ClientMetaInfo,
	}

	if ctx.DCR.TokenRotationIsEnabled {
		resp.RegistrationToken = dc.registrationToken
	}

	return resp, nil
}

func setUpdateDefaults(
	ctx *oidc.Context,
	client *goidc.Client,
	dynamicClient *request,
) error {
	dynamicClient.id = client.ID
	if ctx.DCR.TokenRotationIsEnabled {
		token, err := registrationAccessToken()
		if err != nil {
			return err
		}
		dynamicClient.registrationToken = token
	}

	return setDefaults(ctx, dynamicClient)
}

func fetch(
	ctx *oidc.Context,
	dynamicClientRequest request,
) (
	response,
	error,
) {

	client, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return response{}, err
	}

	return response{
		ID:              client.ID,
		RegistrationURI: registrationURI(ctx, client.ID),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx *oidc.Context,
	dynamicClientRequest request,
) error {
	_, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.id); err != nil {
		return oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not delete the client", err)
	}
	return nil
}

func setDefaults(ctx *oidc.Context, dynamicClient *request) error {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientAuthnSecretBasic
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		secret, err := clientSecret()
		if err != nil {
			return err
		}
		dynamicClient.secret = secret
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	}

	if dynamicClient.IDTokenKeyEncAlg != "" &&
		dynamicClient.IDTokenContentEncAlg == "" {
		dynamicClient.IDTokenContentEncAlg = ctx.User.DefaultContentEncAlg
	}

	if dynamicClient.UserInfoKeyEncAlg != "" &&
		dynamicClient.UserInfoContentEncAlg == "" {
		dynamicClient.UserInfoContentEncAlg = ctx.User.DefaultContentEncAlg
	}

	if dynamicClient.JARMKeyEncAlg != "" &&
		dynamicClient.JARMContentEncAlg == "" {
		dynamicClient.JARMContentEncAlg = ctx.JARM.DefaultContentEncAlg
	}

	if dynamicClient.JARKeyEncAlg != "" &&
		dynamicClient.JARContentEncAlg == "" {
		dynamicClient.JARContentEncAlg = ctx.JAR.DefaultContentEncAlg
	}

	if dynamicClient.CustomAttributes == nil {
		dynamicClient.CustomAttributes = make(map[string]any)
	}

	return nil
}

func newClient(dc request) *goidc.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword(
		[]byte(dc.registrationToken),
		bcrypt.DefaultCost,
	)
	client := &goidc.Client{
		ID:                            dc.id,
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                dc.ClientMetaInfo,
	}

	if dc.AuthnMethod == goidc.ClientAuthnSecretPost ||
		dc.AuthnMethod == goidc.ClientAuthnSecretBasic {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword(
			[]byte(dc.secret),
			bcrypt.DefaultCost,
		)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dc.AuthnMethod == goidc.ClientAuthnSecretJWT {
		client.Secret = dc.secret
	}

	return client
}

func registrationURI(ctx *oidc.Context, id string) string {
	return ctx.BaseURL() + ctx.Endpoint.DCR + "/" + id
}

func protected(
	ctx *oidc.Context,
	dc request,
) (
	*goidc.Client,
	error,
) {
	if dc.id == "" {
		return nil, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid client_id")
	}

	client, err := ctx.Client(dc.id)
	if err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not find the client", err)
	}

	if dc.registrationToken == "" ||
		!client.IsRegistrationAccessTokenValid(dc.registrationToken) {
		return nil, oidcerr.New(oidcerr.CodeAccessDenied, "invalid access token")
	}

	return client, nil
}

func clientID() (string, error) {
	id, err := strutil.Random(idLength)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate the client id", err)
	}
	return "dc-" + id, nil
}

func clientSecret() (string, error) {
	s, err := strutil.Random(secretLength)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate the client secret", err)
	}
	return s, nil
}

func registrationAccessToken() (string, error) {
	token, err := strutil.Random(registrationAccessTokenLength)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate the registration access token", err)
	}
	return token, nil
}
