# go-oidc - A Configurable OpenID Provider built in Go.
[![Go Reference](https://pkg.go.dev/badge/github.com/luikyv/go-oidc.svg)](https://pkg.go.dev/github.com/luikyv/go-oidc)
[![Go Report Card](https://goreportcard.com/badge/github.com/luikyv/go-oidc)](https://goreportcard.com/report/github.com/luikyv/go-oidc)
[![License](https://img.shields.io/github/license/luikyv/go-oidc)](LICENSE)

`go-oidc` is a Go module that provides a configurable Authorization Server with support for OpenID Connect and other standards.

This library implements the following specifications:
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
* [`RFC 7662` - OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
* [`RFC 7009` - OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html)
* [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0 (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)

## Certification
Luiky Vasconcelos has certified that [go-oidc](https://pkg.go.dev/github.com/luikyv/go-oidc) conforms to the following profile of the OpenID Connect™ protocol.
* Basic OP
* FAPI 2.0

[<img src="http://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certification" width="200"/>](https://openid.net/certification/)

## Get Started
To start using the `go-oidc` module in your project, install it with
```
go get github.com/luikyv/go-oidc@latest
```

Once installed, you can instantiate an openid provider and run it as shown below.
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
_ = op.Run(":80")
```

You can then check the default configurations by accessing http://localhost/.well-known/openid-configuration.

## Documentation

### Running the Provider

After instantiating a new provider, the simplest way to run it is
```go
op.Run(":80")
```
For more flexibility, the provider can create an HTTP handler with all endpoints configured.
The example below demonstrates running the provider under TLS:

```go
mux := http.NewServeMux()
mux.Handle("/", op.Handler())

server := &http.Server{
	Addr:    ":443",
	Handler: mux,
}
_ := server.ListenAndServeTLS(certFilePath, certKeyFilePath)
```

### Storage
go-oidc revolves around three entities which are:

- `goidc.Client` is the entity that interacts with the authorization server to request tokens and access protected resources.
- `goidc.AuthnSession` is a short-lived session that stores information about authorization requests.
  It can be used to implement more sophisticated user authentication flows by allowing interactions during the authentication process.
- `goidc.GrantSession` represents the access granted to a client by an entity (either a user or the client itself).
  It holds information about the token issued and the entity who granted access.

`goidc.Client`, `goidc.AuthnSession` and `goidc.GrantSession` are managed by implementations of `goidc.ClientManager`, `goidc.AuthnSessionManager` and `goidc.GrantSessionManager` respectively.

By default, `provider.Provider` uses an in-memory implementation of these interfaces, meaning all stored entities are lost when the server shuts down.

It is highly recommended to replace the default storage with custom implementations to ensure persistence.
For more details, see `provider.WithClientStorage`, `provider.WithAuthnSessionStorage` and `provider.WithGrantSessionStorage`.

### Authentication Policies

For authorization requests (when grant types such as implicit and authorization_code are enabled) which start by default at `/authorize`, users are authenticated with an available `goidc.AuthnPolicy`.

The policy manages user interactions and modifies the `goidc.AuthnSession` to determine how access and ID tokens are issued, including the information they contain. Refer to the fields of `goidc.AuthnSession` for details on what can be modified and how.

The policy below includes a setup function that always returns `true`, meaning the authentication function will execute for all requests.
If the setup function were to return `false`, the authentication function would not be evaluated.

The authentication function renders an HTML page to collect the username and returns `goidc.StatusInProgress`, pausing the flow while awaiting user interaction.

Authentication resumes when a request is made to `/authorize/{callback_id}`.
For example, the HTML page could submit a form via `POST /authorize/{callback_id}` to continue the authentication process.

The **callback ID** is pre-populated in the authentication session and can be accessed via `goidc.AuthnSession.CallbackID`.
Once the user is identified, the authentication process completes successfully by returning `goidc.StatusSuccess`.

If the authentication function returns either `goidc.StatusFailure` or an error, the flow is stopped, and the grant is denied.
```go
policy := NewPolicy(
  "main_policy",
  // Setup function.
  func(_ *http.Request, _ *goidc.Client, _ *goidc.AuthnSession) bool {
    return true
  },
  // Authentication function.
  func(r http.ResponseWriter, w *http.Request, as *goidc.AuthnSession) (AuthnStatus, error) {
    username := r.PostFormValue("username")
    if username == "" {
      renderHTMLPage(w)
      return goidc.StatusInProgress, nil
    }

    if username == "banned_user" {
      return goidc.StatusFailure, errors.New("the user is banned")
    }

    as.Subject = username
    return goidc.StatusSuccess, nil
  },
)

op, err := provider.New(
  ...,
  provider.WithAuthorizationCodeGrant(),
  provider.WithPolicy(policy),
  ...,
)
```

For a more complex example of a `goidc.AuthnPolicy`, check out the examples folder.

### Scopes

go-oidc provides two functions for creating scopes.

`goidc.NewScope` creates a simple scope.
```go
scope := goidc.NewScope("openid")
```

Whereas `goidc.NewDynamicScope` creates a more complex scope where validation logic goes beyond simple string matching.
```go
dynamicScope := goidc.NewDynamicScope("payment", func(requestedScope string) bool {
	return strings.HasPrefix(requestedScope, "payment:")
})
// This results in true.
dynamicScope.Matches("payment:30")
```
Note that this dynamic scope  will appear as "payment" under "scopes_supported" in the /.well-known/openid-configuration endpoint response.

The example below shows how to add the scopes to the `provider.Provider`.
```go
op, _ := provider.New(
  ...,
  provider.WithScopes(goidc.ScopeOpenID, goidc.ScopeOfflineAccess)
  ...,
)
```

### Dynamic Client Registration (DCR)

Dynamic Client Registration (DCR) enables clients to be created and managed dynamically. This feature can be activated by adding the following option to the provider:
```go
op, _ := provider.New(
  ...,
  provider.WithDCR(
    // Function to add custom logic during DCR.
    func(r *http.Request, id string, meta *goidc.ClientMetaInfo) error {
      return nil
    },
    // Function to validate the initial access token.
    func(r *http.Request, initialToken string) error {
      return nil
    },
  ),
  ...,
)
```

`goidc.HandleDynamicClientFunc` is executed first during requests to the DCR endpoint and also for every request to update an existing client.
By default, the DCR endpoint is `/register`, and the Dynamic Client Management (DCM) endpoint is `/register/{client_id}`.

### Mutual TLS (mTLS)

Mutual TLS (mTLS) is a security protocol that ensures both the client and server authenticate each other using TLS certificates. To enable it, configure your provider as follows:
```go
op, _ := provider.New(
  ...,
  provider.WithMTLS(
    // mTLS host.
    "https://matls-go-oidc.com",
    // Function to fetch the client certificate.
    func(r *http.Request) (*x509.Certificate, error) {
      ...
    }
  ),
  ...,
)
```

All endpoints enabled for the provider will be listed under `mtls_endpoint_aliases` in the response of GET `/.well-known/openid-configuration`, using the provided mTLS host.
```json
{
  ...,
  "mtls_endpoint_aliases": {
    ...,
    "token_endpoint": "https://matls-go-oidc.com/token",
    ...,
  },
  ...,
}
```

Keep in mind that `goidc.ClientCertFunc` may be executed multiple times during a single request to the provider. If performance is a concern, consider caching the certificate to avoid redundant computations.

### JWT-Secured Authorization Request (JAR)

JAR, as defined in [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html), allows clients to send authorization requests as signed and optionally encrypted JWTs (request objects) instead of URL query parameters.
```go
op, _ := provider.New(
  ...,
  provider.WithJAR(goidc.RS256, goidc.PS256),
  ...,
)
```

This configures the supported signing algorithms, reflected in `/.well-known/openid-configuration`:
```json
{
  ...,
  "request_parameter_supported": true,
  "request_object_signing_alg_values_supported": ["RS256", "PS256"],
  ...,
}
```

To enable JAR encryption:
```go
op, _ := provider.New(
  ...,
  provider.WithJAR(goidc.RS256, goidc.PS256),
  provider.WithJAREncryption(goidc.RSA_OAEP_256)
  ...,
)
```

which would result in the metadata below
```json
{
  ...,
  "request_parameter_supported": true,
  "request_object_signing_alg_values_supported": ["RS256", "PS256"],
  "request_object_encryption_alg_values_supported": ["RSA_OAEP_256"],
  "request_object_encryption_enc_values_supported": ["A128CBC_HS256"],
  ...,
}
```

To customize JAR content encryption algorithms, use `provider.WithJARContentEncryptionAlgs`.

### JWT-Secured Authorization Response Mode (JARM)

[JARM](https://openid.net/specs/oauth-v2-jarm.html) enhances OAuth 2.0 by returning authorization responses as signed and optionally encrypted JWTs. For this, it defines new response modes: `jwt`, `query.jwt`, `fragment.jwt` and `form_post.jwt`.
```go
op, _ := provider.New(
  ...,
  provider.WithJARM(goidc.RS256, goidc.PS256),
  ...,
)
```

By including the option `provider.WithJARM`, the well known metadata is displayed as follows
```json
{
  ...,
  "authorization_signing_alg_values_supported": ["RS256", "PS256"],
  "response_modes_supported": [
    "jwt",
    "query.jwt",
    "fragment.jwt",
    "form_post.jwt",
    ...,
  ],
  ...,
}
```

To enable JARM encryption:
```go
op, _ := provider.New(
  ...,
  provider.WithJAM(goidc.RS256, goidc.PS256),
  provider.WithJARMEncryption(goidc.RSA_OAEP_256)
  ...,
)
```

which would result in the metadata below
```json
{
  ...,
  "authorization_signing_alg_values_supported": ["RS256", "PS256"],
  "response_modes_supported": [
    ...,
    "query.jwt",
    "fragment.jwt",
    "form_post.jwt",
    ...,
  ],
  "authorization_encryption_alg_values_supported": ["RSA_OAEP_256"],
  "authorization_encryption_enc_values_supported": ["A128CBC_HS256"],
  ...,
}
```

To customize JARM content encryption algorithms, use `provider.WithJARMContentEncryptionAlgs`.
