package authorize

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const errCodeEmpty = goidc.ErrorCode("")

func setUpDeviceAuth(t *testing.T, authenticated bool) (oidc.Context, *goidc.Client, string) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.DeviceAuthorizationIsEnabled = true
	ctx.DeviceAuthorizationLifetimeSecs = 600
	ctx.GenerateDeviceCodeFunc = func() (string, error) { return "test_device_code", nil }
	ctx.GenerateUserCodeFunc = func() (string, error) { return "USERCODE", nil }
	ctx.HandleUserCodeFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }

	client, secret := oidctest.NewClient(t)
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up auth: %v", err)
	}

	policy := goidc.NewPolicy(
		"random_policy_id",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
			as.GrantScopes(as.Scopes)
			return goidc.StatusSuccess, nil
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	if !authenticated {
		client.TokenAuthnMethod = goidc.ClientAuthnNone
		if err := ctx.SaveClient(client); err != nil {
			t.Fatalf("error setting up auth: %v", err)
		}
	}

	return ctx, client, secret
}

func matchErrorCode(t *testing.T, err error, errCode goidc.ErrorCode) {
	t.Helper()
	if errCode != "" {
		if err == nil {
			t.Fatalf("err = nil, want %q", errCode)
		}
		switch oidcErr := err.(type) {
		case goidc.Error:
			if oidcErr.Code != errCode {
				t.Fatalf("err.Code = %q, want %q", oidcErr.Code, errCode)
			}
		default:
			t.Fatalf("err type = %T, want *goidc.Error", err)
		}
	}
}

func deviceMatchInitResp(t *testing.T, resp deviceResponse, want deviceResponse) {
	if diff := cmp.Diff(
		want,
		resp,
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}
}

func deviceMatchInitSess(t *testing.T, ctx oidc.Context, client *goidc.Client, as *goidc.AuthnSession) {
	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	sess := sessions[0]
	as.ID = sess.ID
	as.ClientID = client.ID
	as.Scopes = client.ScopeIDs
	as.CreatedAtTimestamp = sess.CreatedAtTimestamp
	as.ExpiresAtTimestamp = sess.ExpiresAtTimestamp
	as.PolicyID = ctx.Policies[0].ID
	as.DeviceCallbackID = sess.DeviceCallbackID

	if diff := cmp.Diff(
		as,
		sess,
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}
}

func TestInitDeviceAuth_PublicClient(t *testing.T) {
	ctx, client, _ := setUpDeviceAuth(t, false)
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
	}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes: client.ScopeIDs,
		},
	}

	// When
	resp, err := initDeviceAuth(ctx, req)

	// Then
	matchErrorCode(t, err, errCodeEmpty)

	wantResp := deviceResponse{
		DeviceCode:      "test_device_code",
		UserCode:        "USERCODE",
		VerificationURI: ctx.BaseURL() + ctx.EndpointDevice,
		ExpiresIn:       600,
	}

	deviceMatchInitResp(t, resp, wantResp)

	wantSess := &goidc.AuthnSession{
		DeviceCode:           "test_device_code",
		UserCode:             "USERCODE",
		AuthorizationPending: true,
		Authorized:           false,
	}

	deviceMatchInitSess(t, ctx, client, wantSess)
}

func TestInitDeviceAuth_AuthenticatedClient(t *testing.T) {
	// Given
	ctx, client, secret := setUpDeviceAuth(t, true)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes: client.ScopeIDs,
		},
	}

	// When
	resp, err := initDeviceAuth(ctx, req)

	// Then
	matchErrorCode(t, err, errCodeEmpty)

	wantResp := deviceResponse{
		DeviceCode:      "test_device_code",
		UserCode:        "USERCODE",
		VerificationURI: ctx.BaseURL() + ctx.EndpointDevice,
		ExpiresIn:       600,
	}

	deviceMatchInitResp(t, resp, wantResp)

	wantSess := &goidc.AuthnSession{
		DeviceCode:           "test_device_code",
		UserCode:             "USERCODE",
		AuthorizationPending: true,
		Authorized:           false,
	}

	deviceMatchInitSess(t, ctx, client, wantSess)
}
