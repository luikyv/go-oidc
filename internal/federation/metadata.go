package federation

import (
	"reflect"

	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadata struct {
	FederationAuthority *federationAuthority           `json:"federation_entity,omitempty"`
	OpenIDProvider      *discovery.OpenIDConfiguration `json:"openid_provider,omitempty"`
	OpenIDClient        *goidc.ClientMeta              `json:"openid_relying_party,omitempty"`
}

// Merge merges metadata from a subordinate statement (high) with metadata from
// an entity configuration (low). Values from the subordinate statement take
// precedence over values from the entity configuration.
func (subordinate metadata) Merge(config metadata) (metadata, error) {
	subordinate.OpenIDClient = mergeMetadata(subordinate.OpenIDClient, config.OpenIDClient)
	return subordinate, nil
}

func mergeMetadata[T any](subordinate, config *T) *T {
	// Per the federation spec, subordinate statements can only modify/restrict existing metadata, not create it.
	if config == nil {
		return nil
	}
	if subordinate == nil {
		return config
	}
	subordinateVal := reflect.ValueOf(subordinate).Elem()
	configVal := reflect.ValueOf(config).Elem()

	for i := range subordinateVal.NumField() {
		subordinateField := subordinateVal.Field(i)
		if !subordinateField.IsZero() {
			configVal.Field(i).Set(subordinateField)
		}
	}

	return config
}
