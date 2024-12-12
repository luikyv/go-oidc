package federation

import (
	"testing"
)

func TestMetadataPolicy_Merge(t *testing.T) {
	// Given.
	highPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	lowPolicy := metadataPolicy{}

	// When.
	_, err := highPolicy.merge(lowPolicy)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Apply(t *testing.T) {
	// Given.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	statement := openIDEntityStatement{
		Metadata: struct {
			OpenIDAuthority *openIDAuthority "json:\"federation_entity,omitempty\""
			OpenIDProvider  *openIDProvider  "json:\"openid_provider,omitempty\""
			OpenIDClient    *openIDClient    "json:\"openid_relying_party,omitempty\""
		}{
			OpenIDClient: &openIDClient{},
		},
	}

	// When.
	_, err := policy.apply(statement)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}
