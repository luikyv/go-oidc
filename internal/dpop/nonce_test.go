package dpop_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateJWTDPoPNonceChallenge(t *testing.T) {
	tests := []struct {
		name       string
		scope      goidc.DPoPNonceScope
		wantStatus int
		wantAuthn  bool
	}{
		{
			name:       "authorization server",
			scope:      goidc.DPoPNonceScopeAuthorizationServer,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "resource server",
			scope:      goidc.DPoPNonceScopeResourceServer,
			wantStatus: http.StatusUnauthorized,
			wantAuthn:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newNonceManager("fresh_nonce")
			ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
			consumeCalls := 0
			ctx.ConsumeJTIFunc = func(context.Context, string) error {
				consumeCalls++
				return nil
			}
			rec.Header().Add(goidc.HeaderDPoPNonce, "stale_nonce_1")
			rec.Header().Add(goidc.HeaderDPoPNonce, "stale_nonce_2")
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + "/token",
			})

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{NonceScope: test.scope})

			assertOAuthError(t, err, goidc.ErrorCodeUseDPoPNonce, test.wantStatus)
			if got := rec.Header().Values(goidc.HeaderDPoPNonce); len(got) != 1 || got[0] != "fresh_nonce" {
				t.Fatalf("%s = %v, want [fresh_nonce]", goidc.HeaderDPoPNonce, got)
			}
			if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			authn := rec.Header().Get("WWW-Authenticate")
			if test.wantAuthn && !strings.Contains(authn, `DPoP error="use_dpop_nonce"`) {
				t.Fatalf("WWW-Authenticate = %q, want DPoP nonce challenge", authn)
			}
			if !test.wantAuthn && authn != "" {
				t.Fatalf("WWW-Authenticate = %q, want empty", authn)
			}
			if manager.validateCallCount() != 0 {
				t.Fatalf("ValidateNonce() calls = %d, want 0", manager.validateCallCount())
			}
			if consumeCalls != 0 {
				t.Fatalf("ConsumeJTI() calls = %d, want 0", consumeCalls)
			}
		})
	}
}

func TestValidateJWTDPoPNonceAcceptsRecentNonce(t *testing.T) {
	for _, scope := range []goidc.DPoPNonceScope{
		goidc.DPoPNonceScopeAuthorizationServer,
		goidc.DPoPNonceScopeResourceServer,
	} {
		t.Run(string(scope), func(t *testing.T) {
			manager := newNonceManager()
			manager.add(scope, "current_nonce")
			ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + "/token",
				Nonce:  "current_nonce",
			})

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{NonceScope: scope})

			if err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}
			if got := rec.Header().Values(goidc.HeaderDPoPNonce); len(got) != 0 {
				t.Fatalf("%s = %v, want no rotation", goidc.HeaderDPoPNonce, got)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q, want empty", got)
			}
			if !manager.has(scope, "current_nonce") {
				t.Fatal("the reusable nonce was unexpectedly consumed")
			}
		})
	}
}

func TestValidateJWTDPoPNoncePositiveResponseRotation(t *testing.T) {
	manager := newNonceManager()
	manager.nextValues = []string{"next_nonce"}
	manager.add(goidc.DPoPNonceScopeAuthorizationServer, "current_nonce")
	ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    ctx.Host + "/token",
		Nonce:  "current_nonce",
	})

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
	})

	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if got := rec.Header().Values(goidc.HeaderDPoPNonce); len(got) != 1 || got[0] != "next_nonce" {
		t.Fatalf("%s = %v, want [next_nonce]", goidc.HeaderDPoPNonce, got)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if !manager.has(goidc.DPoPNonceScopeAuthorizationServer, "next_nonce") {
		t.Fatal("the replacement nonce was not persisted before validation returned")
	}
}

func TestValidateJWTDPoPNonceMismatch(t *testing.T) {
	manager := newNonceManager("replacement_nonce")
	ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
	consumeCalls := 0
	ctx.ConsumeJTIFunc = func(context.Context, string) error {
		consumeCalls++
		return nil
	}
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    ctx.Host + "/token",
		Nonce:  "unknown_nonce",
	})

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
	})

	assertOAuthError(t, err, goidc.ErrorCodeUseDPoPNonce, http.StatusBadRequest)
	if got := rec.Header().Get(goidc.HeaderDPoPNonce); got != "replacement_nonce" {
		t.Fatalf("%s = %q, want replacement_nonce", goidc.HeaderDPoPNonce, got)
	}
	if consumeCalls != 0 {
		t.Fatalf("ConsumeJTI() calls = %d, want 0", consumeCalls)
	}
}

func TestValidateJWTDPoPNonceIsScopedToIssuer(t *testing.T) {
	manager := newNonceManager("resource_nonce")
	manager.add(goidc.DPoPNonceScopeAuthorizationServer, "authorization_nonce")
	ctx, _ := nonceContext(t, manager, http.MethodGet, "/userinfo")
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodGet,
		URI:    ctx.Host + "/userinfo",
		Nonce:  "authorization_nonce",
	})

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope: goidc.DPoPNonceScopeResourceServer,
	})

	assertOAuthError(t, err, goidc.ErrorCodeUseDPoPNonce, http.StatusUnauthorized)
}

func TestValidateJWTDPoPNonceOperationalErrorsFailClosed(t *testing.T) {
	storeErr := errors.New("nonce store unavailable")

	t.Run("validate", func(t *testing.T) {
		manager := newNonceManager("unused_nonce")
		manager.add(goidc.DPoPNonceScopeAuthorizationServer, "current_nonce")
		manager.validateErr = storeErr
		ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
		consumeCalls := 0
		ctx.ConsumeJTIFunc = func(context.Context, string) error {
			consumeCalls++
			return nil
		}
		proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
			Method: http.MethodPost,
			URI:    ctx.Host + "/token",
			Nonce:  "current_nonce",
		})

		err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
			NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
		})

		if !errors.Is(err, storeErr) {
			t.Fatalf("ValidateJWT() error = %v, want wrapped store error", err)
		}
		assertNotNonceChallenge(t, err, rec)
		if manager.issueCallCount() != 0 {
			t.Fatalf("IssueNonce() calls = %d, want 0", manager.issueCallCount())
		}
		if consumeCalls != 0 {
			t.Fatalf("ConsumeJTI() calls = %d, want 0", consumeCalls)
		}
	})

	t.Run("issue challenge", func(t *testing.T) {
		manager := newNonceManager()
		manager.issueErr = storeErr
		ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
		proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
			Method: http.MethodPost,
			URI:    ctx.Host + "/token",
		})

		err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
			NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
		})

		if !errors.Is(err, storeErr) {
			t.Fatalf("ValidateJWT() error = %v, want wrapped store error", err)
		}
		assertNotNonceChallenge(t, err, rec)
	})

	t.Run("invalid issued nonce", func(t *testing.T) {
		manager := newNonceManager("not a valid nonce")
		ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
		proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
			Method: http.MethodPost,
			URI:    ctx.Host + "/token",
		})

		err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
			NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
		})

		if err == nil || !strings.Contains(err.Error(), "invalid DPoP nonce") {
			t.Fatalf("ValidateJWT() error = %v, want invalid nonce error", err)
		}
		assertNotNonceChallenge(t, err, rec)
	})

	t.Run("invalid positive-response nonce", func(t *testing.T) {
		manager := newNonceManager()
		manager.nextValues = []string{"not a valid nonce"}
		manager.add(goidc.DPoPNonceScopeAuthorizationServer, "current_nonce")
		ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
		proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
			Method: http.MethodPost,
			URI:    ctx.Host + "/token",
			Nonce:  "current_nonce",
		})

		err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
			NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
		})

		if err == nil || !strings.Contains(err.Error(), "invalid DPoP nonce") {
			t.Fatalf("ValidateJWT() error = %v, want invalid nonce error", err)
		}
		assertNotNonceChallenge(t, err, rec)
	})
}

func TestValidateJWTDPoPNonceMissingScopeFailsClosed(t *testing.T) {
	manager := newNonceManager("unused_nonce")
	ctx, rec := nonceContext(t, manager, http.MethodPost, "/token")
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    ctx.Host + "/token",
	})

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{})

	if err == nil || !strings.Contains(err.Error(), "nonce scope") {
		t.Fatalf("ValidateJWT() error = %v, want missing nonce scope error", err)
	}
	assertNotNonceChallenge(t, err, rec)
	if manager.issueCallCount() != 0 || manager.validateCallCount() != 0 {
		t.Fatalf("nonce manager calls = issue %d, validate %d; want none", manager.issueCallCount(), manager.validateCallCount())
	}
}

func TestValidateJWTDPoPNonceConcurrentConsumption(t *testing.T) {
	const requestCount = 16
	manager := newNonceManager()
	manager.singleUse = true
	manager.add(goidc.DPoPNonceScopeAuthorizationServer, "shared_nonce")

	proofs := make([]string, requestCount)
	contexts := make([]oidc.Context, requestCount)
	for i := range proofs {
		proofs[i], _ = oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
			Method: http.MethodPost,
			URI:    "https://example.com/token",
			Nonce:  "shared_nonce",
		})
		contexts[i], _ = nonceContext(t, manager, http.MethodPost, "/token")
	}

	start := make(chan struct{})
	results := make(chan error, requestCount)
	var wg sync.WaitGroup
	for i, proof := range proofs {
		ctx := contexts[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var oauthErr goidc.Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != goidc.ErrorCodeUseDPoPNonce {
			t.Fatalf("concurrent ValidateJWT() error = %v, want use_dpop_nonce", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent consumptions = %d, want 1", successes)
	}
}

func nonceContext(t *testing.T, manager goidc.DPoPNonceManager, method, path string) (oidc.Context, *httptest.ResponseRecorder) {
	t.Helper()
	base := oidctest.NewContext(t)
	base.DPoPEnabled = true
	base.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
	base.DPoPNonceManager = manager
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	return oidc.NewHTTPContext(rec, req, base.Configuration), rec
}

func assertOAuthError(t *testing.T, err error, code goidc.ErrorCode, status int) {
	t.Helper()
	var oauthErr goidc.Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error = %v, want OAuth error", err)
	}
	if oauthErr.Code != code {
		t.Fatalf("error code = %q, want %q", oauthErr.Code, code)
	}
	if oauthErr.StatusCode() != status {
		t.Fatalf("status = %d, want %d", oauthErr.StatusCode(), status)
	}
}

func assertNotNonceChallenge(t *testing.T, err error, rec *httptest.ResponseRecorder) {
	t.Helper()
	var oauthErr goidc.Error
	if errors.As(err, &oauthErr) && oauthErr.Code == goidc.ErrorCodeUseDPoPNonce {
		t.Fatalf("error = %v, must not be a nonce challenge", err)
	}
	if got := rec.Header().Get(goidc.HeaderDPoPNonce); got != "" {
		t.Fatalf("%s = %q, want empty", goidc.HeaderDPoPNonce, got)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty", got)
	}
}

type nonceManager struct {
	mu            sync.Mutex
	valid         map[nonceKey]struct{}
	issueValues   []string
	nextValues    []string
	issueCalls    int
	validateCalls int
	nextCalls     int
	singleUse     bool
	issueErr      error
	validateErr   error
}

type nonceKey struct {
	scope goidc.DPoPNonceScope
	nonce string
}

func newNonceManager(issueValues ...string) *nonceManager {
	return &nonceManager{
		valid:       make(map[nonceKey]struct{}),
		issueValues: issueValues,
	}
}

func (m *nonceManager) IssueNonce(_ context.Context, scope goidc.DPoPNonceScope) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issueCalls++
	if m.issueErr != nil {
		return "", m.issueErr
	}

	nonce := fmt.Sprintf("fresh_nonce_%d", m.issueCalls)
	if m.issueCalls <= len(m.issueValues) {
		nonce = m.issueValues[m.issueCalls-1]
	}
	m.valid[nonceKey{scope: scope, nonce: nonce}] = struct{}{}
	return nonce, nil
}

func (m *nonceManager) ValidateNonce(_ context.Context, scope goidc.DPoPNonceScope, nonce string) (goidc.DPoPNonceValidation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validateCalls++
	if m.validateErr != nil {
		return goidc.DPoPNonceValidation{}, m.validateErr
	}

	key := nonceKey{scope: scope, nonce: nonce}
	if _, ok := m.valid[key]; !ok {
		return goidc.DPoPNonceValidation{}, goidc.ErrNotFound
	}
	if m.singleUse {
		delete(m.valid, key)
	}
	if m.nextCalls < len(m.nextValues) {
		next := m.nextValues[m.nextCalls]
		m.nextCalls++
		m.valid[nonceKey{scope: scope, nonce: next}] = struct{}{}
		return goidc.DPoPNonceValidation{NextNonce: next}, nil
	}
	return goidc.DPoPNonceValidation{}, nil
}

func (m *nonceManager) add(scope goidc.DPoPNonceScope, nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.valid[nonceKey{scope: scope, nonce: nonce}] = struct{}{}
}

func (m *nonceManager) has(scope goidc.DPoPNonceScope, nonce string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.valid[nonceKey{scope: scope, nonce: nonce}]
	return ok
}

func (m *nonceManager) issueCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issueCalls
}

func (m *nonceManager) validateCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.validateCalls
}
