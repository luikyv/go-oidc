package dcr

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type request struct {
	ClientID string `json:"client_id,omitempty"`
	*client.Meta
}

func (req *request) UnmarshalJSON(data []byte) error {
	// Unmarshal into a map to capture all keys.
	var allFields map[string]any
	if err := json.Unmarshal(data, &allFields); err != nil {
		return err
	}

	type alias request
	var reqAlias alias
	if err := json.Unmarshal(data, &reqAlias); err != nil {
		return err
	}

	if reqAlias.Meta == nil {
		reqAlias.Meta = &client.Meta{}
	}
	reqAlias.CustomAttributes = make(map[string]any)
	for key, value := range allFields {
		if !slices.Contains(client.JSONFields, key) {
			reqAlias.CustomAttributes[key] = value
		}
	}

	req.ClientID = reqAlias.ClientID
	req.Meta = reqAlias.Meta
	return nil
}

type response struct {
	ID                string `json:"client_id"`
	Secret            string `json:"client_secret,omitempty"`
	SecretExpiresAt   *int   `json:"client_secret_expires_at,omitempty"`
	RegistrationToken string `json:"registration_access_token,omitempty"`
	RegistrationURI   string `json:"registration_client_uri"`
	*goidc.ClientMeta
}

func (resp response) MarshalJSON() ([]byte, error) {
	// Define a new type to avoid recursion while marshaling.
	type auxResponse response
	attributesBytes, err := json.Marshal(auxResponse(resp))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}

	// Inline the custom attributes.
	delete(rawValues, "custom_attributes")
	maps.Copy(rawValues, resp.CustomAttributes)

	return json.Marshal(rawValues)
}
