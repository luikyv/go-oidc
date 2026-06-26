package vc

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	vcutil "github.com/luikyv/go-oidc/internal/vc/util"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestResolve_Disabled(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = false

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_AuthDetailsOnly_SingleIssuer(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_AuthDetailsOnly_UnknownConfigID(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer:         "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "unknown_cred",
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown credential_configuration_id")
	}
}

func TestResolve_AuthDetailsOnly_MultipleIssuers_WithLocations(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred2": {},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_AuthDetails_ConflictingLocations(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred2": {},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred2",
				"locations":                   []any{"https://issuer2.example.com"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for conflicting locations")
	}
}

func TestResolve_ScopesOnly(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {Scope: goidc.NewScope("vc_scope1")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{Scopes: "vc_scope1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_ScopesConflictIssuers(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {Scope: goidc.NewScope("vc_scope1")},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred2": {Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{Scopes: "vc_scope1 vc_scope2"})
	if err == nil {
		t.Fatal("expected error for scopes referencing different issuers")
	}
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidScope {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidScope)
	}
}

func TestResolve_ResourcesOnly(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_CrossSignalConflict_AuthDetailsVsScopes(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred2": {Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes: "vc_scope2",
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for cross-signal issuer conflict")
	}
}

func TestResolve_CrossSignalConflict_AuthDetailsVsResources(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {},
			},
		},
		{
			Issuer:         "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
		Resources: goidc.Resources{"https://issuer2.example.com"},
	})
	if err == nil {
		t.Fatal("expected error for cross-signal issuer conflict between auth details and resources")
	}
}

func TestResolve_AllThreeSignals_Consistent(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {Scope: goidc.NewScope("vc_scope1")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes: "vc_scope1",
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
			},
		},
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_MissingConfigID(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer:         "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type": string(goidc.AuthDetailTypeOpenIDCredential),
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing credential_configuration_id")
	}
}

func TestResolve_WithResources(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred1": {Scope: goidc.NewScope("vc_scope1")},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
				"cred2": {Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	// Scopes resolve config but no issuer (multiple issuers); resources resolve issuer.
	issuer, configIDs, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes:    "vc_scope1",
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issuer.Issuer != "https://issuer1.example.com" {
		t.Errorf("issuer.ID = %s, want https://issuer1.example.com", issuer.Issuer)
	}
	if len(configIDs) != 1 {
		t.Fatalf("len(configIDs) = %d, want 1", len(configIDs))
	}
	if configIDs[0] != "cred1" {
		t.Errorf("configIDs[0] = %s, want cred1", configIDs[0])
	}
}
