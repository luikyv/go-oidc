package client

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type AuthnRequest struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ID            string
	Secret        string
	AssertionType goidc.ClientAssertionType
	Assertion     string
}

func NewAuthnRequest(req *http.Request) AuthnRequest {
	return AuthnRequest{
		ID:            req.PostFormValue("client_id"),
		Secret:        req.PostFormValue("client_secret"),
		AssertionType: goidc.ClientAssertionType(req.PostFormValue("client_assertion_type")),
		Assertion:     req.PostFormValue("client_assertion"),
	}
}

type DynamicClientRequest struct {
	ID     string
	Secret string
	// This value is filled with the authorization header when creating a client with DCR.
	InitialAccessToken string
	// This value is filled with the authorization header for all DCM requests.
	RegistrationAccessToken string
	goidc.ClientMetaInfo
}

type DynamicClientResponse struct {
	ID                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationURI         string `json:"registration_client_uri"`
	goidc.ClientMetaInfo
}

func (resp DynamicClientResponse) MarshalJSON() ([]byte, error) {

	type dynamicClientResponse DynamicClientResponse
	attributesBytes, err := json.Marshal(dynamicClientResponse(resp))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}

	// Inline the custom attributes.
	delete(rawValues, "custom_attributes")
	for k, v := range resp.CustomAttributes {
		rawValues[k] = v
	}

	return json.Marshal(rawValues)
}
