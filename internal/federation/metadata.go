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

func (high metadata) merge(low metadata) (metadata, error) {
	if low.OpenIDClient != nil {
		var highOpenIDClient goidc.ClientMeta
		if high.OpenIDClient != nil {
			highOpenIDClient = *high.OpenIDClient
		}

		result, err := mergeOpenIDClient(highOpenIDClient, *low.OpenIDClient)
		if err != nil {
			return metadata{}, err
		}
		high.OpenIDClient = &result
	}

	return high, nil
}

// mergeOpenIDClient merges two [goidc.ClientMeta]. Values from high take
// precedence over low. If a field in high is zero, the value from low is used.
func mergeOpenIDClient(high goidc.ClientMeta, low goidc.ClientMeta) (goidc.ClientMeta, error) {
	highV := reflect.ValueOf(&high).Elem()
	lowV := reflect.ValueOf(low)

	for i := 0; i < highV.NumField(); i++ {
		highField := highV.Field(i)
		lowField := lowV.Field(i)

		if highField.IsZero() && !lowField.IsZero() {
			highField.Set(lowField)
		}
	}

	return high, nil
}
