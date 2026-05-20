package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestManagerSessions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *storage.Manager)
	}{
		{
			name: "save session evicts oldest when full",
			run: func(t *testing.T, manager *storage.Manager) {
				// When.
				err := manager.SaveSession(context.Background(), &goidc.AuthnSession{
					ID:        "session_1",
					CreatedAt: 1,
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				err = manager.SaveSession(context.Background(), &goidc.AuthnSession{
					ID:        "session_2",
					CreatedAt: 2,
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Then.
				if len(manager.Sessions) != 1 {
					t.Fatalf("len(manager.Sessions) = %d, want 1", len(manager.Sessions))
				}
				if _, ok := manager.Sessions["session_1"]; ok {
					t.Fatal("expected oldest session to be evicted")
				}
				if _, ok := manager.Sessions["session_2"]; !ok {
					t.Fatal("expected newest session to remain")
				}
			},
		},
		{
			name: "load session by id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Sessions["session_1"] = &goidc.AuthnSession{ID: "session_1"}

				// When.
				session, err := manager.Session(context.Background(), "session_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if session.ID != "session_1" {
					t.Fatalf("session.ID = %q, want %q", session.ID, "session_1")
				}
			},
		},
		{
			name: "load session by id not found",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				_, err := manager.Session(context.Background(), "session_1")

				// Then.
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("err = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
		{
			name: "load session by device code",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Sessions["session_1"] = &goidc.AuthnSession{
					ID:         "session_1",
					DeviceCode: "device_code_1",
				}

				// When.
				session, err := manager.SessionByDeviceCode(context.Background(), "device_code_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if session.ID != "session_1" {
					t.Fatalf("session.ID = %q, want %q", session.ID, "session_1")
				}
			},
		},
		{
			name: "load session by user code",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Sessions["session_1"] = &goidc.AuthnSession{
					ID:       "session_1",
					UserCode: "user_code_1",
				}

				// When.
				session, err := manager.SessionByUserCode(context.Background(), "user_code_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if session.ID != "session_1" {
					t.Fatalf("session.ID = %q, want %q", session.ID, "session_1")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := storage.NewManager(1)
			if test.name == "save session evicts oldest when full" {
				manager = storage.NewManager(1)
			}
			if test.name == "load session by id" || test.name == "load session by id not found" ||
				test.name == "load session by device code" || test.name == "load session by user code" ||
				test.name == "delete session existing and missing" {
				manager = storage.NewManager(2)
			}
			test.run(t, manager)
		})
	}
}

func TestManagerClients(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *storage.Manager)
	}{
		{
			name: "save client evicts oldest when full",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				err := manager.SaveClient(context.Background(), &goidc.Client{ID: "client_1", CreatedAt: 1})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = manager.SaveClient(context.Background(), &goidc.Client{ID: "client_2", CreatedAt: 2})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Then.
				if len(manager.Clients) != 1 {
					t.Fatalf("len(manager.Clients) = %d, want 1", len(manager.Clients))
				}
				if _, ok := manager.Clients["client_1"]; ok {
					t.Fatal("expected oldest client to be evicted")
				}
				if _, ok := manager.Clients["client_2"]; !ok {
					t.Fatal("expected newest client to remain")
				}
			},
		},
		{
			name: "load client by id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Clients["client_1"] = &goidc.Client{ID: "client_1"}

				// When.
				client, err := manager.Client(context.Background(), "client_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if client.ID != "client_1" {
					t.Fatalf("client.ID = %q, want %q", client.ID, "client_1")
				}
			},
		},
		{
			name: "load client by id not found",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				_, err := manager.Client(context.Background(), "client_1")

				// Then.
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("err = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
		{
			name: "delete client existing and missing",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Clients["client_1"] = &goidc.Client{ID: "client_1"}

				// When.
				err := manager.DeleteClient(context.Background(), "client_1")
				if err != nil {
					t.Fatalf("unexpected error deleting existing client: %v", err)
				}
				err = manager.DeleteClient(context.Background(), "missing")
				if err != nil {
					t.Fatalf("unexpected error deleting missing client: %v", err)
				}

				// Then.
				if len(manager.Clients) != 0 {
					t.Fatalf("len(manager.Clients) = %d, want 0", len(manager.Clients))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := storage.NewManager(2)
			if test.name == "save client evicts oldest when full" {
				manager = storage.NewManager(1)
			}
			test.run(t, manager)
		})
	}
}

func TestManagerGrants(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *storage.Manager)
	}{
		{
			name: "save grant evicts oldest when full",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				err := manager.SaveGrant(context.Background(), &goidc.Grant{ID: "grant_1", CreatedAt: 1})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = manager.SaveGrant(context.Background(), &goidc.Grant{ID: "grant_2", CreatedAt: 2})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Then.
				if len(manager.Grants) != 1 {
					t.Fatalf("len(manager.Grants) = %d, want 1", len(manager.Grants))
				}
				if _, ok := manager.Grants["grant_1"]; ok {
					t.Fatal("expected oldest grant to be evicted")
				}
				if _, ok := manager.Grants["grant_2"]; !ok {
					t.Fatal("expected newest grant to remain")
				}
			},
		},
		{
			name: "load grant by id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Grants["grant_1"] = &goidc.Grant{ID: "grant_1"}

				// When.
				grant, err := manager.Grant(context.Background(), "grant_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if grant.ID != "grant_1" {
					t.Fatalf("grant.ID = %q, want %q", grant.ID, "grant_1")
				}
			},
		},
		{
			name: "load grant by id not found",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				_, err := manager.Grant(context.Background(), "grant_1")

				// Then.
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("err = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
		{
			name: "load grant by auth code",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Grants["grant_1"] = &goidc.Grant{ID: "grant_1", AuthCode: "auth_code_1"}

				// When.
				grant, err := manager.GrantByAuthCode(context.Background(), "auth_code_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if grant.ID != "grant_1" {
					t.Fatalf("grant.ID = %q, want %q", grant.ID, "grant_1")
				}
			},
		},
		{
			name: "load grant by refresh token",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Grants["grant_1"] = &goidc.Grant{ID: "grant_1", RefreshToken: "refresh_token_1"}

				// When.
				grant, err := manager.GrantByRefreshToken(context.Background(), "refresh_token_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if grant.ID != "grant_1" {
					t.Fatalf("grant.ID = %q, want %q", grant.ID, "grant_1")
				}
			},
		},
		{
			name: "load grant by auth req id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Grants["grant_1"] = &goidc.Grant{ID: "grant_1", AuthReqID: "auth_req_id_1"}

				// When.
				grant, err := manager.GrantByAuthReqID(context.Background(), "auth_req_id_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if grant.ID != "grant_1" {
					t.Fatalf("grant.ID = %q, want %q", grant.ID, "grant_1")
				}
			},
		},
		{
			name: "load grant by device code",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Grants["grant_1"] = &goidc.Grant{ID: "grant_1", DeviceCode: "device_code_1"}

				// When.
				grant, err := manager.GrantByDeviceCode(context.Background(), "device_code_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if grant.ID != "grant_1" {
					t.Fatalf("grant.ID = %q, want %q", grant.ID, "grant_1")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := storage.NewManager(2)
			if test.name == "save grant evicts oldest when full" {
				manager = storage.NewManager(1)
			}
			test.run(t, manager)
		})
	}
}

func TestManagerTokens(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *storage.Manager)
	}{
		{
			name: "save token evicts oldest when full",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				err := manager.SaveToken(context.Background(), &goidc.Token{ID: "token_1", CreatedAt: 1})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = manager.SaveToken(context.Background(), &goidc.Token{ID: "token_2", CreatedAt: 2})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Then.
				if len(manager.Tokens) != 1 {
					t.Fatalf("len(manager.Tokens) = %d, want 1", len(manager.Tokens))
				}
				if _, ok := manager.Tokens["token_1"]; ok {
					t.Fatal("expected oldest token to be evicted")
				}
				if _, ok := manager.Tokens["token_2"]; !ok {
					t.Fatal("expected newest token to remain")
				}
			},
		},
		{
			name: "load token by id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.Tokens["token_1"] = &goidc.Token{ID: "token_1"}

				// When.
				token, err := manager.Token(context.Background(), "token_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if token.ID != "token_1" {
					t.Fatalf("token.ID = %q, want %q", token.ID, "token_1")
				}
			},
		},
		{
			name: "load token by id not found",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				_, err := manager.Token(context.Background(), "token_1")

				// Then.
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("err = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := storage.NewManager(3)
			if test.name == "save token evicts oldest when full" {
				manager = storage.NewManager(1)
			}
			test.run(t, manager)
		})
	}
}

func TestManagerLogoutSessions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *storage.Manager)
	}{
		{
			name: "save logout session evicts oldest when full",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				err := manager.SaveLogoutSession(context.Background(), &goidc.LogoutSession{ID: "logout_1", CreatedAt: 1})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = manager.SaveLogoutSession(context.Background(), &goidc.LogoutSession{ID: "logout_2", CreatedAt: 2})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Then.
				if len(manager.LogoutSessions) != 1 {
					t.Fatalf("len(manager.LogoutSessions) = %d, want 1", len(manager.LogoutSessions))
				}
				if _, ok := manager.LogoutSessions["logout_1"]; ok {
					t.Fatal("expected oldest logout session to be evicted")
				}
				if _, ok := manager.LogoutSessions["logout_2"]; !ok {
					t.Fatal("expected newest logout session to remain")
				}
			},
		},
		{
			name: "load logout session by id",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.
				manager.LogoutSessions["logout_1"] = &goidc.LogoutSession{ID: "logout_1"}

				// When.
				session, err := manager.LogoutSession(context.Background(), "logout_1")

				// Then.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if session.ID != "logout_1" {
					t.Fatalf("session.ID = %q, want %q", session.ID, "logout_1")
				}
			},
		},
		{
			name: "load logout session by id not found",
			run: func(t *testing.T, manager *storage.Manager) {
				// Given.

				// When.
				_, err := manager.LogoutSession(context.Background(), "logout_1")

				// Then.
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("err = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := storage.NewManager(2)
			if test.name == "save logout session evicts oldest when full" {
				manager = storage.NewManager(1)
			}
			test.run(t, manager)
		})
	}
}
