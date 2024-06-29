package goidc_test

import (
	"fmt"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestAddTokenClaims_HappyPath(t *testing.T) {
	// Given.
	tokenOptions := goidc.TokenOptions{}

	// When.
	tokenOptions.AddTokenClaims(map[string]any{
		"claim": "value",
	})
	// Then.
	if tokenOptions.AdditionalTokenClaims["claim"] != "value" {
		t.Error("the claim was not added")
	}

	// When.
	tokenOptions.AddTokenClaims(map[string]any{
		"claim": "value",
	})
	// Then.
	if tokenOptions.AdditionalTokenClaims["claim"] != "value" {
		t.Error("the claim was not added")
	}
}

func TestAuthorizationParameters_Merge_HappyPath(t *testing.T) {
	// Given.
	insideParams := goidc.AuthorizationParameters{
		RedirectURI:          "https:example1.com",
		State:                "random_state",
		AuthorizationDetails: []goidc.AuthorizationDetail{},
	}
	outsideParams := goidc.AuthorizationParameters{
		RedirectURI: "https:example2.com",
		Nonce:       "random_nonce",
		Claims:      &goidc.ClaimsObject{},
	}

	// When.
	mergedParams := insideParams.Merge(outsideParams)

	// Then.
	if mergedParams.RedirectURI != "https:example1.com" {
		// The parameter from inside should take priority.
		t.Error("the redirect URI is not as expected")
		return
	}

	if mergedParams.State != "random_state" {
		t.Error("the state is not as expected")
		return
	}

	if mergedParams.Nonce != "random_nonce" {
		t.Error("the nonce is not as expected")
		return
	}

	if mergedParams.AuthorizationDetails == nil {
		t.Error("the authorization details are not as expected")
		return
	}

	if mergedParams.Claims == nil {
		t.Error("the claims are not as expected")
		return
	}
}

func TestGetResponseMode_HappyPath(t *testing.T) {
	// Given.
	testCases := []struct {
		params               goidc.AuthorizationParameters
		expectedResponseMode goidc.ResponseMode
	}{
		{
			goidc.AuthorizationParameters{ResponseMode: goidc.QueryResponseMode},
			goidc.QueryResponseMode,
		},
		{
			goidc.AuthorizationParameters{ResponseType: goidc.CodeResponse},
			goidc.QueryResponseMode,
		},
		{
			goidc.AuthorizationParameters{ResponseType: goidc.IDTokenResponse},
			goidc.FragmentResponseMode,
		},
		{
			goidc.AuthorizationParameters{ResponseMode: goidc.JWTResponseMode, ResponseType: goidc.CodeResponse},
			goidc.QueryJWTResponseMode,
		},
		{
			goidc.AuthorizationParameters{ResponseMode: goidc.JWTResponseMode, ResponseType: goidc.IDTokenResponse},
			goidc.FragmentJWTResponseMode,
		},
		{
			goidc.AuthorizationParameters{ResponseMode: goidc.QueryJWTResponseMode},
			goidc.QueryJWTResponseMode,
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i+1),
			func(t *testing.T) {
				// When.
				responseMode := testCase.params.GetResponseMode()

				// Then.
				if testCase.expectedResponseMode != responseMode {
					t.Errorf("response mode not as expected. actual: %s, expected: %s", responseMode, testCase.expectedResponseMode)
				}
			},
		)
	}
}

func TestAuthorizationDetail_GetProperties_HappyPath(t *testing.T) {
	// Given.
	authDetails := goidc.AuthorizationDetail{
		"type":       "random_type",
		"identifier": "random_identifier",
		"actions":    []string{"random_action"},
	}

	// Then.
	if authDetails.GetType() != "random_type" {
		t.Error("type not as expected")
		return
	}

	if authDetails.GetIdentifier() != "random_identifier" {
		t.Error("identifier not as expected")
		return
	}

	if authDetails.GetActions()[0] != "random_action" {
		t.Error("action not as expected")
		return
	}
}
