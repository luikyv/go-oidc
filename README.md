# go-oidc - A Configurable OpenID Provider built in Go.
[![Go Reference](https://pkg.go.dev/badge/github.com/luikyv/go-oidc.svg)](https://pkg.go.dev/github.com/luikyv/go-oidc)
[![Go Report Card](https://goreportcard.com/badge/github.com/luikyv/go-oidc)](https://goreportcard.com/report/github.com/luikyv/go-oidc)

`go-oidc` is a client module that provides a configurable Authorization Server with support for OpenID Connect and other standards.

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
jwk := goidc.JSONWebKey{
  KeyID:     "server_key",
  Key:       key,
  Algorithm: string(goidc.RS256),
  Use:       string(goidc.KeyUsageSignature),
}

op, _ := provider.New(
  goidc.ProfileOpenID,
  "http://localhost",
  func(_ context.Context) (goidc.JSONWebKeySet, error) {
    return goidc.JSONWebKeySet{
      Keys: []goidc.JSONWebKey{jwk},
    }, nil
  },
)
op.Run(":80")
```

You can then check the default configurations by accessing http://localhost/.well-known/openid-configuration.
