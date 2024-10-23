# go-oidc - A Configurable OpenID Provider built in GO.
[![Go Reference](https://pkg.go.dev/badge/github.com/luikyv/go-oidc.svg)](https://pkg.go.dev/github.com/luikyv/go-oidc)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fluikyv%2Fgo-oidc.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fluikyv%2Fgo-oidc?ref=badge_shield)

`go-oidc` is a client module that provides a configurable Authorization Server with support for OpenID Connect and other standards.

This library implements the following specifications:
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [`RFC 6749` - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html)
* [`RFC 7591` - OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.html)
* [`RFC 7592` - OAuth 2.0 Dynamic Client Registration Management Protocol (DCR)](https://www.rfc-editor.org/rfc/rfc7592)
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

## Certification
Luiky Vasconcelos has certified that [go-oidc](https://pkg.go.dev/github.com/luikyv/go-oidc@v0.3.0) conforms to the FAPI 2.0 profile of the OpenID Connect™ protocol.

[<img src="http://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certification" width="200"/>](https://openid.net/certification/)

## Installation
To start using the `go-oidc` module in your project, install it with
```
go get github.com/luikyv/go-oidc@latest
```

## Get Started
Once installed, you can instantiate an openid provider and run it as shown below.
```go
jwksStr := `{
	"keys": [
		{
			"kid": "server_key",
			"p": "3-xp6XC0qLvqjLCCYTeY9Z4r6hAcySsGQDmp-T04vGompCGuAXYkU6iflqEE8J-vGZPghk0YQEdsWYx4H0GQPF_oz4N205N091LAiYUUYy-wIX0rPZ4qKiSdkAaXYNOHvpQMHs-ibi868IBEdvEpvUAHC5Z_zFNcxrTiVK_wuJc",
			"kty": "RSA",
			"q": "mjTPG0kaYyF2UXH5fvb7UQ4oUVocM-i7wyjJndJWVa9vGHSrpXi6aLR-llbfzokiRZPEOCZlCTmK-2oXXLzYEDZCLLigSXq-e3Z71l23c7wmypPaHNoq5XOXOSrEUN8-QLkA3vDthOx_HxNhektBSSeTGsnW_NhgcP5Csov3qQ0",
			"d": "FayeFDvs4ZjjfIMzGou324nh1wMPpkTV25CyYyzKsl-UWEotsE6TUWzDhFDspzJPsQ5Qtwdjms_zaSxnkfz4WTQMwP3QTk6i-6u6Ow73wkJzAZ4mWA-o798oA2EIobMfEg9_sd79DS2bJK5syMsjmJ0pXYrrZSCjaE8OdPNLH9w3ROoXdRqX5QepS0xHzofOYgMVNAOd5sXVmNCPbtgjkPOWSUs-O5WE-0Sqpbkm9mwt89aMRKb8jj1ZBd8t2s12AErBcwR9Pqn-vBwATN_SNxLuspPcZQtR4iKBDTJCDLvlfUVKOp5YSBoanZkldEgkD3sagBUbm242xlhKJ-vwGQ",
			"e": "AQAB",
			"use": "sig",
			"qi": "o9Mlti_fwa981ANQvEnwcrI-3FenGaNBXpn-CAK-YrKNgwP-fDGh9Ok2-c1os5o7H1ARzZisczxn4QrA7_712hwP1BgsO40kOOva36QywfeSgI1WbUJbfb2HEh7fOaZKBirCLc1sXo4kOBeCT4SQ3iSMATDX-y4P1SJkLm1HFlM",
			"dp": "Cfr2iYINe0vM23JujTi2J5RiLq-DKPAy-h_X1JUG91bf3AboQ4ZpfhUQ79zDZJopasFti27aOts0GBWrsPDyJc68iKs6W5nB59gXXsnAq98PQZ7bk4Z-KJyzLR0uGBG1higBFkp42eJfBSMiag67poS5C6osjgXVJ8IeKFojJ4c",
			"alg": "RS256",
			"dq": "NYXc2LCf6wZjRdOUcIATLMgIMGxhW5cNDKjsic3Gz4jLu6ZLKWzk7pCvW0kd91bbwWCPe5m_-dqyJZ9mKncVW1Mp1tHiOH7U_I9cXkQ69323zRpSWy9SMj_TnjD84MELn3VXGwputnNLkCKu876JE3Yb9fFWoH4Nw0pNJiG0vUU",
			"n": "huJo4_i7_uBNiB-wmZr7GIWKH0iUOJqDIir6PFDAgih3yt9zETFpVOn5dngo16VZLM1PTg8vMGOG97TBwPSCi2YGTA2MJTdJQEQ1jETQmkVov_kxR6OmPTZ5XUy-jZ6J9YMkYCKXD7IGIgW5VqkONwF7e8PVUHCc9o4U24F_MHyOv0P3dS9obMqxhr-5pbWHZ3K4ldQzXnpVnS-zV5nTSYa-Yh9lUYK9Qg2eejXPaXWdGFdF7lqtB_Pi6OdUwiDZhnVRBQdLarQHgx8qNU34AOUWvdL77eiqHWGd152_h7I9RObcvPRFbhh-wnx43go78tlgrJyYIMV2oCLs78YOqw"
		}
	]
}`
var jwks jose.JSONWebKeySet
if err := json.Unmarshal([]byte(jwksStr), &jwks); err != nil {
	log.Fatal(err)
}

op := provider.New(
    goidc.ProfileOpenID,
    "http://localhost",
    jwks,
)
op.Run(":80")
```

You can then check the default configurations by accessing http://localhost/.well-known/openid-configuration.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fluikyv%2Fgo-oidc.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fluikyv%2Fgo-oidc?ref=badge_large)