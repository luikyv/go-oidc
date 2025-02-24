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

### Entities
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
The policy is responsible for interacting with the user and modifing the `goidc.AuthnSession` to define how access and ID tokens are issued and with what information.

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
  func(_ *http.Request, _ *Client, _ *AuthnSession) bool {
    return true
  },
  // Authentication function.
  func(r http.ResponseWriter, w *http.Request, as *AuthnSession) (AuthnStatus, error) {
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


Alternatively, the authentication function can return `goidc.StatusInProgress`, which pauses the flow to await user interaction.
This interaction could involve, for example, displaying an HTML page for further user input.

For a more complex example of `goidc.AuthnPolicy`, check out the examples folder.

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
