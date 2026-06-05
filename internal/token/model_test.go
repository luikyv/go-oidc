package token

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNewGrant_NonExpiringRefreshToken(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.RefreshTokenLifetimeSecs = 0
	ctx.RefreshTokenFunc = func(context.Context) string { return "refresh_token" }

	c, _ := oidctest.NewClient(t)

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:     goidc.GrantClientCredentials,
		Subject:  "subject",
		Username: "alice",
		ClientID: c.ID,
		Scopes:   c.ScopeIDs,
		Store:    map[string]any{},
	})
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}

	if grant.RefreshToken != "refresh_token" {
		t.Fatalf("grant.RefreshToken = %q, want %q", grant.RefreshToken, "refresh_token")
	}
	if grant.RefreshTokenExpiresAt != 0 {
		t.Fatalf("grant.RefreshTokenExpiresAt = %d, want 0", grant.RefreshTokenExpiresAt)
	}

	grants := oidctest.Grants(t, ctx)
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	if grants[0].RefreshToken != "refresh_token" {
		t.Fatalf("persisted grant.RefreshToken = %q, want %q", grants[0].RefreshToken, "refresh_token")
	}
	if grants[0].RefreshTokenExpiresAt != 0 {
		t.Fatalf("persisted grant.RefreshTokenExpiresAt = %d, want 0", grants[0].RefreshTokenExpiresAt)
	}
}
