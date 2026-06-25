package vc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func TestRegisterHandlers_OffersDisabled(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		VCISelfEnabled:            true,
		VCISelfCredentialEndpoint: "/credential",
		VCISelfOfferEndpoint:      "/credential_offer",
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/credential_offer/id", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
