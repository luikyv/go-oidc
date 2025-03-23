package dcr

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRequestUnmarshalJSON(t *testing.T) {
	// Given.
	testCases := []struct {
		payload []byte
		want    request
	}{
		{
			[]byte(`{
				"client_name": "Test Client",
				"logo_uri": "https://example.com/logo.png",
				"custom_field_1": "Value 1",
				"custom_field_2": 123
			}`),
			request{
				&goidc.ClientMeta{
					Name:    "Test Client",
					LogoURI: "https://example.com/logo.png",
					CustomAttributes: map[string]any{
						"custom_field_1": "Value 1",
						"custom_field_2": 123.0,
					},
				},
			},
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// Given.
				var req request

				// When.
				err := json.Unmarshal(testCase.payload, &req)

				// Then.
				if err != nil {
					t.Fatal(err)
				}

				if diff := cmp.Diff(req, testCase.want); diff != "" {
					t.Error(diff)
				}
			},
		)
	}
}
