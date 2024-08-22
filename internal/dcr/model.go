package dcr

import (
	"encoding/json"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type request struct {
	id     string
	secret string
	// initialAccessToken holds the value of the authorization header when
	// creating a client with DCR.
	initialAccessToken string
	// registrationAccessToken holds the value of the authorization header for
	// all DCM requests.
	registrationAccessToken string
	goidc.ClientMetaInfo
}

type response struct {
	ID                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationURI         string `json:"registration_client_uri"`
	goidc.ClientMetaInfo
}

func (resp response) MarshalJSON() ([]byte, error) {

	// Define a new type to avoid recursion while marshaling.
	type dcResp response
	attributesBytes, err := json.Marshal(dcResp(resp))
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
