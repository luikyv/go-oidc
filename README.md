# go-oidc

[![Go Reference](https://pkg.go.dev/badge/github.com/luikyv/go-oidc.svg)](https://pkg.go.dev/github.com/luikyv/go-oidc)
[![Go Report Card](https://goreportcard.com/badge/github.com/luikyv/go-oidc)](https://goreportcard.com/report/github.com/luikyv/go-oidc)
[![License](https://img.shields.io/github/license/luikyv/go-oidc)](LICENSE)

A configurable OpenID Connect Provider for Go.

## Supported Specifications

* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [`RFC 6749` - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
* [`RFC 7591` - OAuth 2.0 Dynamic Client Registration Protocol (DCR)](https://www.rfc-editor.org/rfc/rfc7591.html)
* [`RFC 7592` - OAuth 2.0 Dynamic Client Registration Management Protocol (DCM)](https://www.rfc-editor.org/rfc/rfc7592)
* [`RFC 9126` - OAuth 2.0 Pushed Authorization Requests (PAR)](https://www.rfc-editor.org/rfc/rfc9126.html)
* [`RFC 9101` - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
* [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html)
* [`RFC 7636` - Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://www.rfc-editor.org/rfc/rfc7636.html)
* [`RFC 9207` - OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)
* [`RFC 8705` - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705.html)
* [`RFC 9449` - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
* [`RFC 9396` - OAuth 2.0 Rich Authorization Requests (RAR)](https://www.rfc-editor.org/rfc/rfc9396.html)
* [`RFC 8707` - Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
* [`RFC 8628` - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628.html)
* [`RFC 7662` - OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
* [`RFC 7009` - OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html)
* [`RFC 8252` - OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html)
* [FAPI 1.0 Security Profile 1.0 - Part 1: Baseline](https://openid.net/specs/openid-financial-api-part-1-1_0.html)
* [FAPI 1.0 Security Profile 1.0 - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
* [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
* [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0 (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)
* [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
* [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* [OpenID Shared Signals Framework Specification 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
* [OpenID Connect Relying Party Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)

## Certification

Luiky Vasconcelos has certified that [go-oidc](https://pkg.go.dev/github.com/luikyv/go-oidc) conforms to the following profiles of the OpenID Connect™ protocol.
* Basic OP, Implicit OP, Hybrid OP, Config OP and Dynamic OP
* FAPI 1.0
* FAPI 2.0

[<img src="http://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certification" width="200"/>](https://openid.net/certification/)

## Get Started

Install the module:
```
go get github.com/luikyv/go-oidc@latest
```

Create and run a provider:
```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
jwks := goidc.JSONWebKeySet{
  Keys: []goidc.JSONWebKey{{
    KeyID:     "key_id",
    Key:       key,
    Algorithm: "RS256",
  }},
}

op, _ := provider.New(
  "http://localhost",
  nil,
  func(_ context.Context) (goidc.JSONWebKeySet, error) {
    return jwks, nil
  },
)
op.Run(":80")
```

Verify the setup at http://localhost/.well-known/openid-configuration.

## Table of Contents

- [Running the Provider](#running-the-provider)
- [Grants](#grants)
- [Tokens](#tokens)
- [Authorization Code and Implicit Grants](#authorization-code-and-implicit-grants)
- [Refresh Token Grant](#refresh-token-grant)
- [Client Credentials Grant](#client-credentials-grant)
- [JWT Bearer Grant](#jwt-bearer-grant)
- [Client-Initiated Backchannel Authentication (CIBA)](#client-initiated-backchannel-authentication-ciba)
- [Device Code Grant](#device-code-grant)
- [Pushed Authorization Requests (PAR)](#pushed-authorization-requests-par)
- [Authentication Policies](#authentication-policies)
- [Logout](#logout)
- [ID Tokens](#id-tokens)
- [UserInfo Endpoint](#userinfo-endpoint)
- [Token Introspection](#token-introspection)
- [Token Revocation](#token-revocation)
- [Signing and Encryption](#signing-and-encryption)
- [Scopes](#scopes)
- [Dynamic Client Registration](#dynamic-client-registration-dcr)
- [RP Metadata Choices](#rp-metadata-choices)
- [DPoP](#dpop)
- [Mutual TLS](#mutual-tls-mtls)
- [JWT-Secured Authorization Requests (JAR)](#jwt-secured-authorization-request-jar)
- [JWT-Secured Authorization Response Mode (JARM)](#jwt-secured-authorization-response-mode-jarm)
- [Rich Authorization Requests (RAR)](#rich-authorization-requests)
- [Resource Indicators](#resource-indicators)
- [OpenID Federation](#openid-federation)
- [Shared Signals Framework](#shared-signals-framework-ssf)

## Running the Provider

The simplest way to run the provider:
```go
op.Run(":80")
```

For more flexibility, use `op.Handler()` to get an `http.Handler` with all endpoints configured:
```go
mux := http.NewServeMux()
mux.Handle("/", op.Handler())

server := &http.Server{
  Addr:    ":443",
  Handler: mux,
}
server.ListenAndServeTLS(certFilePath, certKeyFilePath)
```

## Grants

`goidc.Grant` represents what was authorized after the user grants access, or
after the client is authorized directly in non-user flows such as
`client_credentials`.

It is the canonical record of the authorization state. A grant may contain:

- the subject and optional username
- the client ID
- granted scopes
- authorization details
- resource indicators
- proof-of-possession bindings such as DPoP or mTLS thumbprints
- flow-specific identifiers such as authorization code, refresh token, device code, or `auth_req_id`

A grant is created after the authorization step succeeds. For example:

- in the authorization code flow, it is created when the user completes authentication and consent
- in CIBA or device flows, it is created when the pending interaction is approved
- in `client_credentials`, it is created directly from the validated token request

`goidc.Token` is derived from a grant. Tokens can narrow scopes, resources, or
authorization details, but they always originate from one grant through
`Token.GrantID`.

This means one grant can produce multiple tokens over time, especially when:

- refresh tokens are enabled
- the client narrows scopes or resources on subsequent token requests
- the same authorization is redeemed more than once through allowed flows

In practice, `goidc.Grant` is the long-lived authorization state, while
`goidc.Token` is one issued credential under that state.

## Tokens

`goidc.Token` represents one issued access token.

Access tokens are opaque by default. If you configure JWT access tokens, the
serialized token value may become self-contained, but go-oidc still creates and
stores a `goidc.Token` record for it.

The access token format and lifetime are controlled by
`provider.WithTokenOptions(...)`. This option receives the current
`goidc.Grant` and `goidc.Client` and returns a `goidc.TokenOptions` value for
that issuance.

For example, to issue JWT access tokens:

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithTokenOptions(func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
    return goidc.NewJWTTokenOptions(goidc.RS256, 600)
  }),
)
```

Use `goidc.NewOpaqueTokenOptions(...)` to keep opaque access tokens, or
`goidc.NewJWTTokenOptions(...)` to issue JWT access tokens.

Additional access token claims can be added with
`provider.WithTokenClaims(...)`. The function receives the issued
`goidc.Token` and its source `goidc.Grant`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithTokenClaims(func(_ context.Context, token *goidc.Token, grant *goidc.Grant) map[string]any {
    return map[string]any{
      "roles":  grant.Store["roles"],
      "tenant": grant.Store["tenant"],
    }
  }),
)
```

It is created from a `goidc.Grant` and captures the exact authorization state
attached to that token at issuance time. A token may therefore contain:

- its own ID
- the associated `GrantID`
- the subject and client ID
- the active scopes for that token
- authorization details
- resource indicators
- proof-of-possession bindings such as DPoP or mTLS thumbprints
- issuance and expiration timestamps
- token format and token type

A token is not the same thing as a grant. The grant is the durable record of
what was authorized; the token is one credential issued under that record.
Because of that, the token may hold a subset of the grant data. For example, a
refresh token request can issue a new access token with narrower scopes or
resources while keeping the same underlying grant.

Each token has its own lifetime. When a new token is issued from the same
grant, the previous token is not implicitly the same logical credential; it is
a distinct `goidc.Token` with its own ID, timestamps, and confirmation data.

This is true for both opaque and JWT access tokens: the runtime token value may
be different, but the server-side token metadata is always persisted through the
configured token manager.

## Authorization Code and Implicit Grants

The authorization code, implicit, and hybrid flows are enabled through
`provider.WithAuthCodeGrant(...)`.

This option does two things:

- enables the `authorization_code` grant
- registers the response types accepted at the authorization endpoint

The response types you pass determine which flows are available:

- `goidc.ResponseTypeCode` enables the authorization code flow
- `goidc.ResponseTypeToken` or `goidc.ResponseTypeIDToken` enable implicit flows
- combined response types such as `goidc.ResponseTypeCodeAndIDToken` enable hybrid flows

Example with only authorization code:

```go
manager := storage.NewManager(1000)

op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithAuthCodeGrant(manager, goidc.ResponseTypeCode),
)
```

Example with authorization code, implicit, and hybrid response types:

```go
manager := storage.NewManager(1000)

op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithAuthCodeGrant(
    manager,
    goidc.ResponseTypeCode,
    goidc.ResponseTypeToken,
    goidc.ResponseTypeIDToken,
    goidc.ResponseTypeCodeAndToken,
    goidc.ResponseTypeCodeAndIDToken,
  ),
)
```

If you also want refresh tokens, enable them separately with
`provider.WithRefreshTokenGrant(...)`.

## Refresh Token Grant

The refresh token grant is enabled with `provider.WithRefreshTokenGrant(...)`.

```go
manager := storage.NewManager(1000)

op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithAuthCodeGrant(manager, goidc.ResponseTypeCode),
  provider.WithRefreshTokenGrant(manager),
)
```

When this grant is enabled, `goidc.Grant` may carry a refresh token. Later,
when the client calls the token endpoint with `grant_type=refresh_token`, the
provider loads that existing grant, validates the request, and issues a new
`goidc.Token` under the same grant.

This means the refresh token grant does not create a new authorization. It
reuses an existing one.

By default, the same refresh token remains associated with the grant until it
expires. To rotate refresh tokens on each use, add
`provider.WithRefreshTokenRotation()`.

You can also customize the refresh token lifetime with
`provider.WithRefreshTokenLifetime(...)`.

## Client Credentials Grant

The client credentials grant is enabled with
`provider.WithClientCredentialsGrant()`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithClientCredentialsGrant(),
)
```

This flow does not involve an end-user, an authentication session, or consent
screen. The client authenticates directly at the token endpoint and, if the
request is valid, the provider creates a `goidc.Grant` and issues a
`goidc.Token` for the client itself.

In this case, the grant represents what the client was authorized to access,
not what a user delegated. The resulting token is therefore tied to the client
rather than to a user authentication event.

## [JWT Bearer Grant](https://www.rfc-editor.org/rfc/rfc7523.html)

The JWT bearer grant is enabled with `provider.WithJWTBearerGrant(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithJWTBearerGrant(func(ctx context.Context, assertion string) (string, error) {
    return "subject", nil
  }),
)
```

This enables the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant type.
When a token request uses that grant, go-oidc delegates assertion handling to
the function passed to `WithJWTBearerGrant(...)`.

That function receives the raw assertion and must validate it according to your
deployment rules. It returns the subject represented by the assertion, or an
error if the assertion is invalid.

If the assertion is accepted, the provider creates a `goidc.Grant` for that
subject and issues a `goidc.Token` from it. This makes the JWT bearer grant a
direct token flow, similar to `client_credentials`, but driven by an external
assertion instead of a client-only authorization.

Use `provider.WithJWTBearerGrantClientAuthnRequired()` if the client must also
authenticate in addition to presenting the bearer assertion.

## [Client-Initiated Backchannel Authentication (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)

CIBA is enabled with `provider.WithCIBAGrant(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithCIBAGrant(
    manager,
    goidc.CIBADeliveryModePoll,
    goidc.CIBADeliveryModePing,
    goidc.CIBADeliveryModePush,
  ),
)
```

In this flow, the client starts authentication through the backchannel
authentication endpoint and receives an `auth_req_id`. At that point, there is
still no `goidc.Grant`. The provider stores a pending `goidc.AuthnSession`
associated with that `auth_req_id`.

Later, when the user approves or denies the request, the provider resolves that
pending session:

- if access is granted, the session becomes a `goidc.Grant`
- if access is denied, the provider notifies the client according to the
  configured delivery mode
- if the client polls the token endpoint before completion, the request returns
  `authorization_pending`

Once approved, the client exchanges the `auth_req_id` at the token endpoint
using the CIBA grant type and receives tokens derived from the newly created
grant.

The delivery modes available to clients are configured directly on
`provider.WithCIBAGrant(...)`.

## [Device Code Grant](https://www.rfc-editor.org/rfc/rfc8628.html)

The device code grant is enabled with `provider.WithDeviceGrant(...)`.

```go
manager := storage.NewManager(1000)

op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithDeviceGrant(
    manager,
    promptUserCodePage,
    confirmationPage,
  ),
)
```

This flow starts at the device authorization endpoint. After the client is
validated, the provider creates a pending `goidc.AuthnSession` containing a
`device_code` and a `user_code`.

The user then visits the device verification endpoint and enters the
`user_code`. From there, the configured authentication policy runs against that
pending session:

- if authentication succeeds, the session becomes a `goidc.Grant`
- if authentication is still in progress, the session is persisted and can be
  resumed
- if authentication fails, the session is deleted and the request is denied

Later, the client exchanges the `device_code` at the token endpoint using the
device code grant type and receives tokens derived from the resulting grant.

`WithDeviceGrant(...)` also requires two render functions:

- one to prompt the user for the `user_code`
- one to render the confirmation page after successful authorization

## [Pushed Authorization Requests (PAR)](https://www.rfc-editor.org/rfc/rfc9126.html)

PAR is enabled with `provider.WithPAR(manager)` and can be made mandatory with
`provider.WithPARRequired(manager)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithAuthCodeGrant(manager, goidc.ResponseTypeCode),
  provider.WithPAR(manager),
)
```

When the client calls the PAR endpoint, the provider validates the pushed
request and stores it as a short-lived `goidc.AuthnSession`. The response
contains a `request_uri` that identifies that stored session.

Later, the client calls the authorization endpoint with that `request_uri`.
At that point, go-oidc loads the stored session and continues the authorization
flow from it.

In practice, PAR changes where the authorization parameters are validated and
persisted:

- the initial validation happens at the PAR endpoint
- the resulting `request_uri` points to the stored authorization session
- the later authorization request reuses that stored state instead of starting
  from scratch

If JAR is also enabled, the pushed request may carry the request object and the
stored session will reflect the validated JAR content.

The PAR endpoint lifetime can be customized with `provider.WithPARLifetime(...)`.

## Authentication Policies

Authorization requests (starting at `/authorize` by default) are handled by
`goidc.AuthnPolicy`.

Each policy has two parts:

1. `SetUp`: decides whether the policy applies to the current request and
   session.
2. `Authenticate`: performs the user interaction and authentication work.

When a request reaches the authorization endpoint, go-oidc creates or loads a
`goidc.AuthnSession`, selects the first policy whose `SetUp` function returns
`true`, and then calls `Authenticate`.

The authentication function returns one of:

- `goidc.StatusSuccess`: authentication succeeded. The session must contain the
  data needed to create the grant, especially `Subject`.
- `goidc.StatusPending`: the flow is suspended and the session is persisted.
  The user agent can then continue the flow by calling
  `/authorize/{session_id}`.
- `goidc.StatusFailure` or an error: authentication fails and the
  authorization request is denied.

```go
policy := goidc.NewPolicy(
  "main_policy",
  func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
    return true
  },
  func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
    username := r.PostFormValue("username")
    if username == "" {
      renderHTMLPage(w)
      return goidc.StatusPending, nil
    }

    if username == "banned_user" {
      return goidc.StatusFailure, errors.New("the user is banned")
    }

    as.Subject = username
    return goidc.StatusSuccess, nil
  },
)

op, _ := provider.New(
  ...,
  provider.WithAuthCodeGrant(manager, goidc.ResponseTypeCode),
  provider.WithPolicies(policy),
  ...,
)
```

For more examples, see the [`examples`](examples/) folder.

## [Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

RP-initiated logout is enabled with `provider.WithLogout(...)`.

```go
logoutPolicy := goidc.NewLogoutPolicy(
  "main_logout_policy",
  func(_ *http.Request, _ *goidc.LogoutSession, _ *goidc.Client) bool {
    return true
  },
  func(w http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession, _ *goidc.Client) (goidc.Status, error) {
    w.WriteHeader(http.StatusNoContent)
    return goidc.StatusSuccess, nil
  },
)

op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithLogout(manager, func(w http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) error {
    w.WriteHeader(http.StatusNoContent)
    return nil
  }),
  provider.WithLogoutPolicies(logoutPolicy),
)
```

This enables the logout endpoint, which is `/logout` by default. A logout
request may identify the relying party with `client_id` or `id_token_hint`,
and may also include `post_logout_redirect_uri` and `state`.

When a logout request is accepted, go-oidc creates a `goidc.LogoutSession`,
selects the first matching `goidc.LogoutPolicy` configured through
`provider.WithLogoutPolicies(...)`, and runs it. Like authentication policies,
a logout policy can complete immediately or return `goidc.StatusPending`
and resume later through the stored logout session.

On success, go-oidc:

- redirects to `post_logout_redirect_uri` when one was provided and validated
- includes `state` on that redirect when present
- otherwise calls the default post-logout handler passed to `WithLogout(...)`

The first argument to `provider.WithLogout(...)` is the logout session manager
used to store pending logout sessions. Use
`provider.WithLogoutSessionTimeoutSecs(...)` to control how long a pending
logout session remains valid, and `provider.WithLogoutEndpoint(...)` to
override the default endpoint path.

## ID Tokens

ID tokens are signed JWTs that represent the authentication event for the
subject.

go-oidc issues ID tokens from the same `goidc.Grant` used for access token
issuance. Additional ID token claims can be added with
`provider.WithIDTokenClaims(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithIDTokenClaims(func(_ context.Context, grant *goidc.Grant) map[string]any {
    return map[string]any{
      "acr":   "urn:example:loa:2",
      "roles": grant.Store["roles"],
    }
  }),
)
```

By default, ID tokens are signed. The provider-side signing and lifetime
settings are controlled with:

- `provider.WithIDTokenSignatureAlgs(...)`
- `provider.WithIDTokenLifetime(...)`

If you want to support encrypted ID tokens, enable it in the provider with:

- `provider.WithIDTokenEncryption(...)`
- `provider.WithIDTokenContentEncryptionAlgs(...)`

The client metadata can then choose the signing and encryption algorithms it
requires through the standard ID token settings.

## UserInfo Endpoint

The UserInfo endpoint is enabled by default at `/userinfo`.

It is called with an access token and returns claims about the authenticated
subject. The access token must:

- be active
- include the `openid` scope
- satisfy any proof-of-possession binding such as DPoP or mTLS

The response starts from the subject in the `goidc.Grant`. Additional claims
can be added with `provider.WithUserInfoClaims(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithClaims("email", "name"),
  provider.WithUserInfoClaims(func(_ context.Context, grant *goidc.Grant) map[string]any {
    return map[string]any{
      "email": grant.Store["email"],
      "name":  grant.Store["name"],
    }
  }),
)
```

By default, the endpoint returns a JSON object. go-oidc only signs or encrypts
the UserInfo response when that behavior is enabled in the provider and the
client metadata is configured to require it. The provider-side options are:

- `provider.WithUserInfoSignatureAlgs(...)`
- `provider.WithUserInfoEncryption(...)`
- `provider.WithUserInfoContentEncryptionAlgs(...)`

Use `provider.WithUserInfoEndpoint(...)` to override the default endpoint path.

## [Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)

Token introspection is enabled with `provider.WithTokenIntrospection(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithTokenIntrospection(func(_ context.Context, c *goidc.Client, token *goidc.Token) bool {
    return true
  }),
)
```

This enables the introspection endpoint, which is `/introspect` by default.
The client must authenticate to that endpoint. For each introspection request,
the function passed to `WithTokenIntrospection(...)` is called with the
authenticated client and the resolved token and must return whether that client
is allowed to introspect it.

In this implementation, access token introspection is backed by the persisted
`goidc.Token` record, even when the access token itself is issued as a JWT.
Refresh token introspection resolves the corresponding `goidc.Grant`, so the
server can report whether that refresh token is still active.

If the token does not exist, is expired, or is otherwise inactive, the endpoint
returns an inactive introspection response instead of an OAuth error.

Use `provider.WithTokenIntrospectionEndpoint(...)` to override the default
endpoint path.

## [Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html)

Token revocation is enabled with `provider.WithTokenRevocation(...)`.

```go
op, _ := provider.New(
  "http://localhost",
  manager,
  jwksFunc,
  provider.WithTokenRevocation(func(_ context.Context, c *goidc.Client) bool {
    return true
  }),
)
```

This enables the revocation endpoint, which is `/revoke` by default. The client
must authenticate to that endpoint. For each revocation request, the function
passed to `WithTokenRevocation(...)` is called with the authenticated client
and must return whether that client is allowed to use the revocation endpoint.

In this implementation, refresh token revocation is grant-based. If the
refresh token is active and belongs to the authenticated client, the provider
deletes the underlying `goidc.Grant` and all stored `goidc.Token` records
associated with that grant.

Access token revocation deletes only the presented access token by default.
Use `provider.WithTokenRevocationDeleteGrantOnAccessToken()` if you want
access token revocation to also delete the underlying grant and related tokens.

If the token does not exist, is already inactive, or cannot be found, the
revocation request still succeeds without exposing token state.

Use `provider.WithTokenRevocationEndpoint(...)` to override the default
endpoint path.

## Signing and Encryption

When creating a `provider.Provider`, a JWKS function must be provided. This function returns the keys used for signing and encryption. It should typically return both private and public key material.

Every algorithm configured for the provider must have a corresponding JWK in the JWKS.

```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
jwks := goidc.JSONWebKeySet{
  Keys: []goidc.JSONWebKey{{
    KeyID:     "key_id",
    Key:       key,
    Algorithm: "RS256",
  }},
}

op, _ := provider.New(
  goidc.ProfileOpenID,
  "http://localhost",
  func(_ context.Context) (goidc.JSONWebKeySet, error) {
    return jwks, nil
  },
)
```

If direct access to private keys is unavailable or granular control over signing is needed, the JWKS function can return only public key material. In that case, `provider.WithSignerFunc` must be added:
```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
jwks := goidc.JSONWebKeySet{
  Keys: []goidc.JSONWebKey{{
    KeyID:     "key_id",
    Key:       key.Public(),
    Algorithm: "RS256",
  }},
}

op, _ := provider.New(
  goidc.ProfileOpenID,
  "http://localhost",
  func(_ context.Context) (goidc.JSONWebKeySet, error) {
    return jwks, nil
  },
  provider.WithSignerFunc(func(_ context.Context, _ goidc.SignatureAlgorithm) (kid string, signer crypto.Signer, err error) {
    return "key_id", key, nil
  }),
)
```

Similarly, if server-side decryption is needed (e.g., for encrypted JARs), configure `provider.WithDecrypterFunc`.

ID tokens are signed using **RS256** by default. Use `provider.WithIDTokenSignatureAlgs` to change the default or add additional algorithms.

Access tokens are **opaque** by default. To customize this, provide a `goidc.TokenOptionsFunc`:
```go
op, _ := provider.New(
  ...,
  provider.WithTokenOptions(func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
    return goidc.NewJWTTokenOptions(goidc.RS256, 600)
  }),
  ...,
)
```

Use `goidc.NewJWTTokenOptions` for JWT access tokens or `goidc.NewOpaqueTokenOptions` for opaque ones.

Refresh tokens are always opaque.

## Scopes

`goidc.NewScope` creates a scope matched by exact string comparison:
```go
scope := goidc.NewScope("openid")
```

`goidc.NewDynamicScope` creates a scope with custom matching logic:
```go
paymentScope := goidc.NewDynamicScope("payment", func(requestedScope string) bool {
  return strings.HasPrefix(requestedScope, "payment:")
})
paymentScope.Matches("payment:30") // true
```
Dynamic scopes appear by their base name (e.g., "payment") in `scopes_supported`.

```go
op, _ := provider.New(
  ...,
  provider.WithScopes(goidc.ScopeOpenID, goidc.ScopeOfflineAccess),
  ...,
)
```

## [Dynamic Client Registration (DCR)](https://www.rfc-editor.org/rfc/rfc7591.html)

DCR allows clients to register and update themselves dynamically:
```go
op, _ := provider.New(
  ...,
  provider.WithDCR(),
  ...,
)
```

Use `provider.WithDCRHandleClientFunc` to run custom logic during registration and update requests, such as validation or setting default metadata values.

Use `provider.WithDCRValidateInitialTokenFunc` (`goidc.DCRValidateInitialTokenFunc`) to validate the initial access token during registration. Omit this option to skip validation.

By default, the DCR endpoint is `/register` and the management endpoint is `/register/{client_id}`.

To rotate the registration access token on each update request, add `provider.WithDCRTokenRotation()`.

## [RP Metadata Choices](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)

The RP Metadata Choices extension allows clients to advertise priority-ordered lists of preferred algorithms and methods during registration. The server resolves each list to the best mutually supported value.

```go
op, _ := provider.New(
  ...,
  provider.WithDCR(),
  provider.WithRPMetadataChoices(),
  ...,
)
```

A client may include a priority list alongside (or instead of) a single value. For example:

```json
{
  "redirect_uris": ["https://client.example.com/callback"],
  "id_token_signing_alg_values_supported": ["PS256", "RS256", "ES256"]
}
```

The server selects the first value from the list it supports and returns the resolved value in the registration response:

```json
{
  "client_id": "s6BhdRkqt3",
  "redirect_uris": ["https://client.example.com/callback"],
  "id_token_signed_response_alg": "PS256"
}
```

If the client also provides the singular field, it must be present in the priority list.

## [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)

DPoP is enabled with `provider.WithDPoP(...)` and can be made mandatory with
`provider.WithDPoPRequired(...)`.

```go
op, _ := provider.New(
  ...,
  provider.WithDPoP(goidc.ES256),
  ...,
)
```

When a valid DPoP proof is sent, go-oidc binds the resulting grant and tokens
to the proof key thumbprint. Tokens issued under that binding are exposed as
`DPoP` tokens instead of bearer tokens.

When a bound token is used later, the client must send a matching DPoP proof
again. The server validates the DPoP JWT and checks that it proves possession
of the key associated with the token.

DPoP can participate in multiple stages of the flow depending on what is
enabled:

- authorization requests, including PAR
- token issuance
- token usage and proof-of-possession validation

## Mutual TLS (mTLS)

mTLS enables client authentication and certificate-bound access tokens via TLS certificates:
```go
op, _ := provider.New(
  ...,
  provider.WithMTLS(
    "https://matls-go-oidc.com",
    func(context.Context) (*x509.Certificate, error) {
      ...
    },
  ),
  ...,
)
```

All enabled endpoints are listed under `mtls_endpoint_aliases` in the discovery response:
```json
{
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://matls-go-oidc.com/token"
  }
}
```

The certificate function (`goidc.ClientCertFunc`) may be called multiple times per request. Consider caching the result if extraction is expensive.

## [JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)

JAR allows clients to send authorization requests as signed (and optionally encrypted) JWTs:
```go
op, _ := provider.New(
  ...,
  provider.WithJAR(goidc.RS256, goidc.PS256),
  ...,
)
```

This adds the following to the discovery response:
```json
{
  "request_parameter_supported": true,
  "request_object_signing_alg_values_supported": ["RS256", "PS256"]
}
```

To enable encryption:
```go
provider.WithJAREncryption(goidc.RSA_OAEP_256)
```

To customize content encryption algorithms, use `provider.WithJARContentEncryptionAlgs`.

## [JWT-Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)

JARM returns authorization responses as signed (and optionally encrypted) JWTs, adding the response modes `jwt`, `query.jwt`, `fragment.jwt` and `form_post.jwt`:
```go
op, _ := provider.New(
  ...,
  provider.WithJARM(goidc.RS256, goidc.PS256),
  ...,
)
```

To enable encryption:
```go
provider.WithJARMEncryption(goidc.RSA_OAEP_256)
```

To customize content encryption algorithms, use `provider.WithJARMContentEncryptionAlgs`.

## [Rich Authorization Requests (RAR)](https://www.rfc-editor.org/rfc/rfc9396.html)

RAR allows clients to request fine-grained access using structured `authorization_details` objects. Each detail has a `type` field that maps to a registered handler.

```go
op, _ := provider.New(
  ...,
  provider.WithRAR("payment_initiation"),
  ...,
)
```

When using the `authorization_code` or `refresh_token` grant types, the client may request a subset of the originally granted authorization details. Provide `provider.WithRARCompareDetailsFunc` to enforce consistency between the granted and requested sets:

```go
provider.WithRARCompareDetailsFunc(func(ctx context.Context, requested, granted []goidc.AuthDetail) error {
  // Verify that every requested detail is consistent with the granted ones.
  return nil
})
```

## [Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)

Resource Indicators are enabled with `provider.WithResourceIndicators(...)`.

```go
op, _ := provider.New(
  ...,
  provider.WithResourceIndicators(
    "https://api.example.com",
    "https://ledger.example.com",
  ),
  ...,
)
```

This allows clients to send the `resource` parameter in authorization and token
requests. The configured values are the only resource indicators the provider
accepts.

When enabled, the granted resources are carried in the resulting
`goidc.AuthnSession`, `goidc.Grant`, and `goidc.Token`. Access token responses
also return the selected resources.

When using `authorization_code`, `refresh_token`, `device_code`, or CIBA token
requests, the client may ask for a subset of the originally granted resources.
The provider rejects resources that were not granted or that are not part of
the configured allowed list.

Use `provider.WithResourceIndicatorsRequired(...)` if every authorization
request must include a `resource` parameter.

## [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html)

[OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) establishes trust dynamically through signed entity statements, allowing federated clients to authenticate without prior manual registration.

```go
op, _ := provider.New(
  ...,
  provider.WithOpenIDFederation(
    func(_ context.Context) (goidc.JSONWebKeySet, error) {
      return fedJWKS, nil
    },
    "https://trust-anchor.example.com",
  ),
  provider.WithOpenIDFedAuthorityHints("https://intermediate.example.com"),
  ...,
)
```

The entity configuration is exposed at `GET /.well-known/openid-federation`.

### Client Registration Types

Federated clients can use automatic or explicit registration:
```go
provider.WithOpenIDFedClientRegistrationTypes(
  goidc.ClientRegistrationTypeAutomatic,
  goidc.ClientRegistrationTypeExplicit,
)
```

With **automatic** registration, the provider resolves the trust chain by fetching entity configurations and subordinate statements. With **explicit** registration, the client provides the trust chain directly.

### Trust Marks

Require specific trust marks from clients:
```go
provider.WithOpenIDFedRequiredTrustMarksFunc(
  func(_ context.Context, _ *goidc.Client) []goidc.TrustMark {
    return []goidc.TrustMark{"https://trust-anchor.example.com/marks/certified"}
  },
)
```

Include trust marks in the provider's entity configuration:
```go
provider.WithOpenIDFedTrustMark(
  "https://trust-anchor.example.com/marks/certified",
  "https://trust-mark-issuer.example.com",
)
```

### Additional Options

```go
provider.WithOpenIDFedSignatureAlgs(goidc.RS256, goidc.PS256)
provider.WithOpenIDFedTrustChainMaxDepth(5)
provider.WithOpenIDFedOrganizationName("Example Organization")
provider.WithOpenIDFedHTTPClientFunc(func(_ context.Context) *http.Client {
  return customHTTPClient
})
```

## Shared Signals Framework (SSF)

The [Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) allows the provider to act as an SSF transmitter, publishing Security Event Tokens (SETs) to receivers. go-oidc supports [CAEP](https://openid.net/specs/openid-caep-1_0.html) and [RISC](https://openid.net/specs/openid-risc-profile-specification-1_0.html) event types.

```go
op, _ := provider.New(
  ...,
  provider.WithSSF(
    func(_ context.Context) (goidc.JSONWebKeySet, error) {
      return ssfJWKS, nil
    },
    func(ctx context.Context) (goidc.SSFReceiver, error) {
      return goidc.SSFReceiver{ID: "receiver"}, nil
    },
  ),
  provider.WithSSFEventTypes(goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange),
  provider.WithSSFDeliveryMethods(goidc.SSFDeliveryMethodPoll, goidc.SSFDeliveryMethodPush),
  ...,
)
```

The transmitter configuration is exposed at `GET /.well-known/ssf-configuration`.

Push delivery ([RFC 8935](https://datatracker.ietf.org/doc/html/rfc8935)) sends SETs to a receiver-provided endpoint. Poll delivery ([RFC 8936](https://datatracker.ietf.org/doc/html/rfc8936)) lets receivers fetch pending events from `/ssf/poll`.

To publish events:
```go
op.PublishSSFEvent(ctx, streamID, goidc.SSFEvent{
  Type: goidc.SSFEventTypeCAEPSessionRevoked,
  Subject: goidc.SSFSubject{
    Format: goidc.SSFSubjectFormatEmail,
    Email:  "user@example.com",
  },
})
```

Additional options:
```go
// Allow receivers to update stream status (enabled/paused/disabled).
provider.WithSSFEventStreamStatusManagement()
// Allow receivers to add/remove subjects from a stream.
provider.WithSSFEventStreamSubjectManagement()
// Allow receivers to request verification events.
provider.WithSSFEventStreamVerification(func(ctx context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
  // Schedule the verification event for async delivery.
  return nil
})
```

For production, replace the in-memory SSF storage with persistent implementations using `provider.WithSSFEventStreamManager` and `provider.WithSSFEventPollManager`.

For a complete example, see [`examples/ssf`](examples/ssf).
