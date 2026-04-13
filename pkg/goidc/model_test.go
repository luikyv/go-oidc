package goidc_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestProfileIsFAPI(t *testing.T) {
	testCases := []struct {
		profile goidc.Profile
		want    bool
	}{
		{goidc.ProfileFAPI1, true},
		{goidc.ProfileFAPI2, true},
		{goidc.ProfileOpenID, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.profile), func(t *testing.T) {
			if got := tc.profile.IsFAPI(); got != tc.want {
				t.Errorf("IsFAPI() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestResponseTypeContains verifies that ResponseType.Contains correctly
// identifies individual response types within a composite value
// (OIDC Core §3, OAuth 2.0 Multiple Response Type Encoding).
func TestResponseTypeContains(t *testing.T) {
	testCases := []struct {
		name     string
		rt       goidc.ResponseType
		contains goidc.ResponseType
		want     bool
	}{
		{"code in code", goidc.ResponseTypeCode, goidc.ResponseTypeCode, true},
		{"code in code id_token", goidc.ResponseTypeCodeAndIDToken, goidc.ResponseTypeCode, true},
		{"id_token in code id_token", goidc.ResponseTypeCodeAndIDToken, goidc.ResponseTypeIDToken, true},
		{"token not in code", goidc.ResponseTypeCode, goidc.ResponseTypeToken, false},
		{"token in code token", goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeToken, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rt.Contains(tc.contains); got != tc.want {
				t.Errorf("Contains(%s) = %t, want %t", tc.contains, got, tc.want)
			}
		})
	}
}

// TestResponseTypeIsImplicit verifies that implicit response types are correctly
// identified (OIDC Core §3.2, §3.3).
func TestResponseTypeIsImplicit(t *testing.T) {
	testCases := []struct {
		rt   goidc.ResponseType
		want bool
	}{
		{goidc.ResponseTypeCode, false},
		{goidc.ResponseTypeIDToken, true},
		{goidc.ResponseTypeToken, true},
		{goidc.ResponseTypeCodeAndIDToken, true},
		{goidc.ResponseTypeCodeAndToken, true},
		{goidc.ResponseTypeIDTokenAndToken, true},
		{goidc.ResponseTypeCodeAndIDTokenAndToken, true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rt), func(t *testing.T) {
			if got := tc.rt.IsImplicit(); got != tc.want {
				t.Errorf("IsImplicit() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestResponseModeIsJARM(t *testing.T) {
	testCases := []struct {
		rm   goidc.ResponseMode
		want bool
	}{
		{goidc.ResponseModeQueryJWT, true},
		{goidc.ResponseModeFragmentJWT, true},
		{goidc.ResponseModeFormPostJWT, true},
		{goidc.ResponseModeJWT, true},
		{goidc.ResponseModeJSONJWT, true},
		{goidc.ResponseModeQuery, false},
		{goidc.ResponseModeFragment, false},
		{goidc.ResponseModeFormPost, false},
		{goidc.ResponseModeJSON, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rm), func(t *testing.T) {
			if got := tc.rm.IsJARM(); got != tc.want {
				t.Errorf("IsJARM() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestResponseModeIsPlain(t *testing.T) {
	testCases := []struct {
		rm   goidc.ResponseMode
		want bool
	}{
		{goidc.ResponseModeQuery, true},
		{goidc.ResponseModeFragment, true},
		{goidc.ResponseModeFormPost, true},
		{goidc.ResponseModeJSON, true},
		{goidc.ResponseModeQueryJWT, false},
		{goidc.ResponseModeFragmentJWT, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rm), func(t *testing.T) {
			if got := tc.rm.IsPlain(); got != tc.want {
				t.Errorf("IsPlain() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestResponseModeIsQuery(t *testing.T) {
	testCases := []struct {
		rm   goidc.ResponseMode
		want bool
	}{
		{goidc.ResponseModeQuery, true},
		{goidc.ResponseModeQueryJWT, true},
		{goidc.ResponseModeFragment, false},
		{goidc.ResponseModeFormPost, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rm), func(t *testing.T) {
			if got := tc.rm.IsQuery(); got != tc.want {
				t.Errorf("IsQuery() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestResponseModeIsJSON(t *testing.T) {
	testCases := []struct {
		rm   goidc.ResponseMode
		want bool
	}{
		{goidc.ResponseModeJSON, true},
		{goidc.ResponseModeJSONJWT, true},
		{goidc.ResponseModeQuery, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rm), func(t *testing.T) {
			if got := tc.rm.IsJSON(); got != tc.want {
				t.Errorf("IsJSON() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestCIBATokenDeliveryModeIsNotificationMode validates the CIBA token delivery
// mode classification per OpenID CIBA §5.
func TestCIBATokenDeliveryModeIsNotificationMode(t *testing.T) {
	testCases := []struct {
		mode goidc.CIBATokenDeliveryMode
		want bool
	}{
		{goidc.CIBADeliveryModePoll, false},
		{goidc.CIBADeliveryModePing, true},
		{goidc.CIBADeliveryModePush, true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.mode), func(t *testing.T) {
			if got := tc.mode.IsNotificationMode(); got != tc.want {
				t.Errorf("IsNotificationMode() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestCIBATokenDeliveryModeIsPollableMode validates the CIBA token delivery
// mode classification per OpenID CIBA §5.
func TestCIBATokenDeliveryModeIsPollableMode(t *testing.T) {
	testCases := []struct {
		mode goidc.CIBATokenDeliveryMode
		want bool
	}{
		{goidc.CIBADeliveryModePoll, true},
		{goidc.CIBADeliveryModePing, true},
		{goidc.CIBADeliveryModePush, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.mode), func(t *testing.T) {
			if got := tc.mode.IsPollableMode(); got != tc.want {
				t.Errorf("IsPollableMode() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestAuthorizationDetailType(t *testing.T) {
	testCases := []struct {
		name   string
		detail goidc.AuthDetail
		want   goidc.AuthDetailType
	}{
		{
			"with type",
			goidc.AuthDetail{"type": "payment", "amount": 100},
			"payment",
		},
		{
			"missing type",
			goidc.AuthDetail{"amount": 100},
			"",
		},
		{
			"non-string type",
			goidc.AuthDetail{"type": 123},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.detail.Type(); got != tc.want {
				t.Errorf("Type() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNewScope(t *testing.T) {
	// Given.
	scope := goidc.NewScope("openid")

	// Then.
	if scope.ID != "openid" {
		t.Errorf("ID = %s, want openid", scope.ID)
	}
	if !scope.Matches("openid") {
		t.Error("Matches(\"openid\") = false, want true")
	}
	if scope.Matches("profile") {
		t.Error("Matches(\"profile\") = true, want false")
	}
}

func TestNewDynamicScope(t *testing.T) {
	// Given.
	scope := goidc.NewDynamicScope("payment", func(requested string) bool {
		return len(requested) > 8 && requested[:8] == "payment:"
	})

	// Then.
	if scope.ID != "payment" {
		t.Errorf("ID = %s, want payment", scope.ID)
	}
	if !scope.Matches("payment:100") {
		t.Error("Matches(\"payment:100\") = false, want true")
	}
	if scope.Matches("payment") {
		t.Error("Matches(\"payment\") = true, want false")
	}
}

func TestNewJWTTokenOptions(t *testing.T) {
	// When.
	opts := goidc.NewJWTTokenOptions(goidc.RS256, 3600)

	// Then.
	if opts.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", opts.Format, goidc.TokenFormatJWT)
	}
	if opts.JWTSigAlg != goidc.RS256 {
		t.Errorf("JWTSigAlg = %s, want %s", opts.JWTSigAlg, goidc.RS256)
	}
	if opts.LifetimeSecs != 3600 {
		t.Errorf("LifetimeSecs = %d, want 3600", opts.LifetimeSecs)
	}
}

func TestNewOpaqueTokenOptions(t *testing.T) {
	// When.
	opts := goidc.NewOpaqueTokenOptions(600)

	// Then.
	if opts.Format != goidc.TokenFormatOpaque {
		t.Errorf("Format = %s, want %s", opts.Format, goidc.TokenFormatOpaque)
	}
	if opts.LifetimeSecs != 600 {
		t.Errorf("LifetimeSecs = %d, want 600", opts.LifetimeSecs)
	}
}

// TestResourcesUnmarshalJSON_SingleValue validates that the resource parameter
// can be deserialized from a single string value (RFC 8707 §2).
func TestResourcesUnmarshalJSON_SingleValue(t *testing.T) {
	// Given.
	data := []byte(`"https://api.example.com"`)

	// When.
	var resources goidc.Resources
	if err := json.Unmarshal(data, &resources); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	want := goidc.Resources{"https://api.example.com"}
	if diff := cmp.Diff(resources, want); diff != "" {
		t.Error(diff)
	}
}

// TestResourcesUnmarshalJSON_Array validates that the resource parameter
// can be deserialized from an array (RFC 8707 §2).
func TestResourcesUnmarshalJSON_Array(t *testing.T) {
	// Given.
	data := []byte(`["https://api1.example.com","https://api2.example.com"]`)

	// When.
	var resources goidc.Resources
	if err := json.Unmarshal(data, &resources); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	want := goidc.Resources{"https://api1.example.com", "https://api2.example.com"}
	if diff := cmp.Diff(resources, want); diff != "" {
		t.Error(diff)
	}
}

func TestResourcesMarshalJSON_SingleValue(t *testing.T) {
	// Given.
	resources := goidc.Resources{"https://api.example.com"}

	// When.
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	if string(data) != `"https://api.example.com"` {
		t.Errorf("json = %s, want single string", string(data))
	}
}

func TestResourcesMarshalJSON_Array(t *testing.T) {
	// Given.
	resources := goidc.Resources{"https://api1.example.com", "https://api2.example.com"}

	// When.
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	if string(data) != `["https://api1.example.com","https://api2.example.com"]` {
		t.Errorf("json = %s, want array", string(data))
	}
}

// TestClaimsObjectEssentials verifies extraction of essential claims
// (OIDC Core §5.5.1).
func TestClaimsObjectEssentials(t *testing.T) {
	// Given.
	claims := goidc.ClaimsObject{
		IDToken: map[string]goidc.ClaimObjectInfo{
			"auth_time": {IsEssential: true},
			"acr":       {IsEssential: true, Values: []string{"urn:mace:incommon:iap:silver"}},
			"sub":       {IsEssential: false},
		},
		UserInfo: map[string]goidc.ClaimObjectInfo{
			"email":          {IsEssential: true},
			"email_verified": {IsEssential: false},
		},
	}

	// When.
	idTokenEssentials := claims.IDTokenEssentials()
	userInfoEssentials := claims.UserInfoEssentials()

	// Then.
	if len(idTokenEssentials) != 2 {
		t.Errorf("len(IDTokenEssentials) = %d, want 2", len(idTokenEssentials))
	}
	if len(userInfoEssentials) != 1 {
		t.Errorf("len(UserInfoEssentials) = %d, want 1", len(userInfoEssentials))
	}
}

// TestClaimsObjectClaim verifies claim lookup by name (OIDC Core §5.5).
func TestClaimsObjectClaim(t *testing.T) {
	// Given.
	claims := goidc.ClaimsObject{
		IDToken: map[string]goidc.ClaimObjectInfo{
			"acr": {IsEssential: true, Values: []string{"urn:mace:incommon:iap:silver"}},
		},
		UserInfo: map[string]goidc.ClaimObjectInfo{
			"email": {IsEssential: true},
		},
	}

	// When.
	acrClaim, acrOK := claims.IDTokenClaim("acr")
	_, missingOK := claims.IDTokenClaim("sub")
	emailClaim, emailOK := claims.UserInfoClaim("email")

	// Then.
	if !acrOK {
		t.Error("IDTokenClaim(\"acr\") not found")
	}
	if !acrClaim.IsEssential {
		t.Error("acr claim should be essential")
	}
	if missingOK {
		t.Error("IDTokenClaim(\"sub\") should not be found")
	}
	if !emailOK {
		t.Error("UserInfoClaim(\"email\") not found")
	}
	if !emailClaim.IsEssential {
		t.Error("email claim should be essential")
	}
}

// TestTokenInfoMarshalJSON verifies that additional token claims are inlined
// in the JSON output (RFC 7662 §2.2).
func TestTokenInfoMarshalJSON(t *testing.T) {
	// Given.
	info := goidc.TokenInfo{
		IsActive: true,
		ClientID: "client1",
		AdditionalClaims: map[string]any{
			"custom_claim": "custom_value",
		},
	}

	// When.
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unexpected error unmarshalling: %v", err)
	}

	if result["active"] != true {
		t.Errorf("active = %v, want true", result["active"])
	}
	if result["client_id"] != "client1" {
		t.Errorf("client_id = %v, want client1", result["client_id"])
	}
	if result["custom_claim"] != "custom_value" {
		t.Errorf("custom_claim = %v, want custom_value", result["custom_claim"])
	}
}

func TestApplyMiddlewares(t *testing.T) {
	// Given.
	var order []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})
	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1")
			next.ServeHTTP(w, r)
		})
	}
	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2")
			next.ServeHTTP(w, r)
		})
	}

	// When.
	h := goidc.ApplyMiddlewares(handler, mw1, mw2)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	// Then.
	// Middlewares wrap in order, so mw2 is outermost.
	want := []string{"mw2", "mw1", "handler"}
	if diff := cmp.Diff(order, want); diff != "" {
		t.Error(diff)
	}
}

// TestErrorCodeStatusCode verifies HTTP status codes for OAuth 2.0 error codes
// (RFC 6749 §5.2).
func TestErrorCodeStatusCode(t *testing.T) {
	testCases := []struct {
		code goidc.ErrorCode
		want int
	}{
		{goidc.ErrorCodeAccessDenied, http.StatusForbidden},
		{goidc.ErrorCodeInvalidClient, http.StatusUnauthorized},
		{goidc.ErrorCodeInvalidToken, http.StatusUnauthorized},
		{goidc.ErrorCodeUnauthorizedClient, http.StatusUnauthorized},
		{goidc.ErrorCodeInternalError, http.StatusInternalServerError},
		{goidc.ErrorCodeInvalidRequest, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidGrant, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidScope, http.StatusBadRequest},
		{goidc.ErrorCodeUnsupportedGrantType, http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(string(tc.code), func(t *testing.T) {
			if got := tc.code.StatusCode(); got != tc.want {
				t.Errorf("StatusCode() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestErrorStatusCode_CustomOverride verifies that WithStatusCode overrides the
// default status code derived from the error code.
func TestErrorStatusCode_CustomOverride(t *testing.T) {
	// Given.
	err := goidc.NewError(goidc.ErrorCodeInvalidRequest, "bad request").
		WithStatusCode(http.StatusConflict)

	// When.
	got := err.StatusCode()

	// Then.
	if got != http.StatusConflict {
		t.Errorf("StatusCode() = %d, want %d", got, http.StatusConflict)
	}
}

// TestErrorUnwrap verifies that WrapError properly chains errors for use with
// errors.Is/errors.As.
func TestErrorUnwrap(t *testing.T) {
	// Given.
	inner := errors.New("database connection failed")
	err := goidc.WrapError(goidc.ErrorCodeInternalError, "internal error", inner)

	// Then.
	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the wrapped error")
	}
}

// TestErrorMarshalJSON verifies that Error serializes according to RFC 6749 §5.2.
func TestErrorMarshalJSON(t *testing.T) {
	// Given.
	err := goidc.NewError(goidc.ErrorCodeInvalidRequest, "missing parameter").
		WithURI("https://example.com/error")

	// When.
	data, jsonErr := json.Marshal(err)
	if jsonErr != nil {
		t.Fatalf("unexpected error: %v", jsonErr)
	}

	// Then.
	var result map[string]string
	if unmarshalErr := json.Unmarshal(data, &result); unmarshalErr != nil {
		t.Fatalf("unexpected error: %v", unmarshalErr)
	}

	want := map[string]string{
		"error":             "invalid_request",
		"error_description": "missing parameter",
		"error_uri":         "https://example.com/error",
	}
	if diff := cmp.Diff(result, want, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}
}
