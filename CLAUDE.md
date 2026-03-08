# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go library (`github.com/luikyv/go-oidc`) implementing an OpenID Connect Provider with support for OAuth 2.0, FAPI 1.0/2.0, CIBA, SSF, and Federation. Go 1.24+.

## Commands

```bash
make test              # Run all tests: go test ./pkg/... ./internal/...
make lint              # Lint: golangci-lint run ./pkg/... ./internal/...
make test-coverage     # Generate coverage HTML report

# Single test
go test ./internal/token/... -run TestGenerateGrant_RefreshTokenGrant -v

# Conformance suite (requires Docker)
make run-cs            # Start conformance suite
make cs-oidc-tests     # Run OIDC conformance tests
```

## Architecture

### Package Layout

- **`pkg/goidc`** — Base models and interfaces the developer interacts with in their implementation: `Client`, `AuthnSession`, `Grant`, `Token`, their `Manager` interfaces for storage, error codes, JOSE types, middleware, and constants.
- **`pkg/provider`** — The OpenID Provider itself. `New()` constructs a provider with functional options, validation, and defaults.
- **`internal/`** — All implementation logic, organized by feature domain:
  - `oidc/` — `Context` (wraps `http.ResponseWriter`, `*http.Request`, `*Configuration`) and `Configuration` (all server settings + manager references).
  - `authorize/` — Authorization endpoint logic.
  - `token/` — Token endpoint: authorization code, refresh token, client credentials, JWT bearer, CIBA grants, and introspection.
  - `dcr/` — Dynamic Client Registration.
  - `discovery/` — Well-known metadata endpoints.
  - `joseutil/` — JOSE/JWT helpers (signing, encryption, key selection). Uses `go-jose/go-jose/v4`.
  - `client/` — Client authentication (secret, private_key_jwt, mTLS, etc.).
  - `dpop/` — DPoP proof validation.
  - `federation/` — OpenID Federation.
  - `ssf/` — Shared Signals Framework.
  - `oidctest/` — Test helpers: `NewContext()`, `NewClient()`, `PrivateJWKS()`, etc.
  - `strutil/`, `timeutil/`, `hashutil/` — Small utility packages.

### Key Patterns

- **`oidc.Context`** is the central request-scoped object passed everywhere. It embeds the server `Configuration` and provides access to all managers (SaveClient, SaveGrant, SaveToken, etc.).
- **Test setup**: Create `oidc.Context` via `oidctest.NewContext(t)`, configure fields directly on the context, create clients with `oidctest.NewClient(t)`, then call internal functions. For HTTP handler tests, use `httptest.NewRecorder()` + `httptest.NewRequest()` + `oidc.NewHTTPContext()`.
- **Error handling**: Functions return `error`, typically `goidc.Error` with a `Code` field (e.g., `goidc.ErrorCodeInvalidRequest`). Tests check error codes with `errors.As(err, &oidcErr)`.
- **`AuthnSession`** embeds `AuthorizationParameters` — fields like `CodeChallenge`, `Scopes`, `RedirectURI` come from the embedded struct, not directly on `AuthnSession`.

## Linting

Uses golangci-lint v2 with ~22 extra linters. Notable enabled linters: `errcheck`, `gocritic`, `revive`, `unconvert`, `noctx`, `testifylint`, `mirror`, `perfsprint`. Run `make lint` before committing.

## Spec Reference Table

| Package | Relevant Specs |
|---|---|
| `internal/authorize` | RFC 6749 §4.1–§4.2 (Authorization Endpoint), RFC 9126 (PAR), RFC 9101 (JAR), OpenID Connect Core §3 |
| `internal/token` | RFC 6749 §5.1–§5.2 (Token Endpoint), RFC 7636 (PKCE), RFC 7523 (JWT Bearer), RFC 8693 (Token Exchange), OpenID Connect Core §3.1.3 (Token Endpoint), CIBA §10–§11 |
| `internal/token` (introspection) | RFC 7662 (Token Introspection) |
| `internal/token` (revocation) | RFC 7009 (Token Revocation) |
| `internal/client` | RFC 6749 §2.3 (Client Authentication), RFC 7523 §2.2 (private_key_jwt), RFC 8705 §2 (mTLS) |
| `internal/dcr` | RFC 7591 (Dynamic Client Registration), RFC 7592 (Client Management) |
| `internal/authorize` (CIBA) | OpenID Connect CIBA §7–§8 |
| `internal/federation` | OpenID Federation 1.0 |
| `internal/dpop` | RFC 9449 (DPoP) |
| `internal/userinfo` | OpenID Connect Core §5.3 (UserInfo Endpoint) |
| `internal/discovery` | RFC 8414 (Authorization Server Metadata), OpenID Connect Discovery 1.0 |

### Spec URLs for Fetching

- RFC 6749: https://www.rfc-editor.org/rfc/rfc6749
- RFC 7009: https://www.rfc-editor.org/rfc/rfc7009
- RFC 7523: https://www.rfc-editor.org/rfc/rfc7523
- RFC 7591: https://www.rfc-editor.org/rfc/rfc7591
- RFC 7636: https://www.rfc-editor.org/rfc/rfc7636
- RFC 7662: https://www.rfc-editor.org/rfc/rfc7662
- RFC 8705: https://www.rfc-editor.org/rfc/rfc8705
- RFC 9101: https://www.rfc-editor.org/rfc/rfc9101
- RFC 9126: https://www.rfc-editor.org/rfc/rfc9126
- RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
- CIBA: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- OpenID Federation: https://openid.net/specs/openid-federation-1_0.html
