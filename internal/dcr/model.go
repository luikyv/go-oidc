package dcr

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type request struct {
	*client.Client
}

func (r *request) UnmarshalJSON(data []byte) error {
	// Unmarshal into a map to capture all keys.
	var allFields map[string]any
	if err := json.Unmarshal(data, &allFields); err != nil {
		return err
	}

	var c client.Client
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	c.CustomAttributes = make(map[string]any)
	for key, value := range allFields {
		if !slices.Contains(client.JSONFields, key) {
			c.CustomAttributes[key] = value
		}
	}

	r.Client = &c

	return nil
}

type response struct {
	ID                string `json:"client_id"`
	Secret            string `json:"client_secret,omitempty"`
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
