package dcr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestHandleCreate(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	body, _ := json.Marshal(c.ClientMeta) //nolint:errchkjson
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleCreate(ctx)

	// Then.
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v", err)
	}
	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Error("response should contain client_id")
	}
}

func TestHandleCreate_InvalidContentType(t *testing.T) {
	// Given.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	req.Header.Set("Content-Type", "text/plain")
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleCreate(ctx)

	// Then.
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
}

func TestHandleCreate_InvalidJSON(t *testing.T) {
	// Given.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleCreate(ctx)

	// Then.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleGet(t *testing.T) {
	// Given.
	regToken := "reg_token"
	c, _ := oidctest.NewClient(t)
	c.RegistrationToken = regToken
	ctx := oidctest.NewContext(t)
	if err := ctx.SaveClient(c); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/register/"+c.ID, nil)
	req.Header.Set("Authorization", "Bearer "+regToken)
	req.SetPathValue("client_id", c.ID)
	httpCtx := oidc.NewHTTPContext(rec, req, ctx.Configuration)

	// When.
	handleGet(httpCtx)

	// Then.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v", err)
	}
	if resp["client_id"] != c.ID {
		t.Errorf("client_id = %v, want %s", resp["client_id"], c.ID)
	}
}

func TestHandleGet_NoToken(t *testing.T) {
	// Given.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/register/some_id", nil)
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleGet(ctx)

	// Then.
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v", err)
	}
	if resp["error"] != string(goidc.ErrorCodeAccessDenied) {
		t.Errorf("error = %v, want %s", resp["error"], goidc.ErrorCodeAccessDenied)
	}
}

func TestHandleUpdate(t *testing.T) {
	// Given.
	regToken := "reg_token"
	c, _ := oidctest.NewClient(t)
	c.RegistrationToken = regToken
	ctx := oidctest.NewContext(t)
	if err := ctx.SaveClient(c); err != nil {
		t.Fatal(err)
	}

	c.Name = "Updated Name"
	body, err := json.Marshal(c.ClientMeta)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/register/"+c.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+regToken)
	req.SetPathValue("client_id", c.ID)
	httpCtx := oidc.NewHTTPContext(rec, req, ctx.Configuration)

	// When.
	handleUpdate(httpCtx)

	// Then.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleUpdate_InvalidContentType(t *testing.T) {
	// Given.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/register/some_id", nil)
	req.Header.Set("Content-Type", "text/xml")
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleUpdate(ctx)

	// Then.
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
}

func TestHandleUpdate_NoToken(t *testing.T) {
	// Given.
	body, err := json.Marshal(goidc.ClientMeta{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/register/some_id", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleUpdate(ctx)

	// Then.
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v", err)
	}
	if resp["error"] != string(goidc.ErrorCodeAccessDenied) {
		t.Errorf("error = %v, want %s", resp["error"], goidc.ErrorCodeAccessDenied)
	}
}

func TestHandleDelete(t *testing.T) {
	// Given.
	regToken := "reg_token"
	c, _ := oidctest.NewClient(t)
	c.RegistrationToken = regToken
	ctx := oidctest.NewContext(t)
	if err := ctx.SaveClient(c); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/register/"+c.ID, nil)
	req.Header.Set("Authorization", "Bearer "+regToken)
	req.SetPathValue("client_id", c.ID)
	httpCtx := oidc.NewHTTPContext(rec, req, ctx.Configuration)

	// When.
	handleDelete(httpCtx)

	// Then.
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHandleDelete_NoToken(t *testing.T) {
	// Given.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/register/some_id", nil)
	ctx := newHTTPContext(t, rec, req)

	// When.
	handleDelete(ctx)

	// Then.
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v", err)
	}
	if resp["error"] != string(goidc.ErrorCodeAccessDenied) {
		t.Errorf("error = %v, want %s", resp["error"], goidc.ErrorCodeAccessDenied)
	}
}

func TestRegisterHandlers(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.DCRIsEnabled = true
	mux := http.NewServeMux()

	// When.
	RegisterHandlers(mux, ctx.Configuration)

	// Then — just verify no panic and routes are registered.
	// We do a quick smoke test by sending a request.
	c, _ := oidctest.NewClient(t)
	body, err := json.Marshal(c.ClientMeta)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.DCREndpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Error("POST handler should be registered")
	}
}

func TestRegisterHandlers_Disabled(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.DCRIsEnabled = false
	mux := http.NewServeMux()

	// When.
	RegisterHandlers(mux, ctx.Configuration)

	// Then.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.DCREndpoint, nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (routes should not be registered)", rec.Code, http.StatusNotFound)
	}
}

func newHTTPContext(t *testing.T, w http.ResponseWriter, r *http.Request) oidc.Context {
	t.Helper()
	ctx := oidctest.NewContext(t)
	return oidc.NewHTTPContext(w, r, ctx.Configuration)
}
