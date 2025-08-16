package dcr

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type request struct {
	*goidc.ClientMeta
}

func (r *request) UnmarshalJSON(data []byte) error {
	// Unmarshal into a map to capture all keys.
	var allFields map[string]any
	if err := json.Unmarshal(data, &allFields); err != nil {
		return err
	}

	var info goidc.ClientMeta
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	info.CustomAttributes = make(map[string]any)
	knownKeys := jsonKeys(info)
	for key, value := range allFields {
		if !slices.Contains(knownKeys, key) {
			info.CustomAttributes[key] = value
		}
	}

	r.ClientMeta = &info

	return nil
}

// jsonKeys returns a slice of JSON field names for a given struct.
func jsonKeys(v any) []string {
	var keys []string
	val := reflect.ValueOf(v)
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")

		if tag != "" && tag != "-" {
			keys = append(keys, strings.Split(tag, ",")[0])
		}
	}
	return keys
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
