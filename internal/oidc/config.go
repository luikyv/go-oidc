package oidc

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Configuration struct {
	Profile goidc.Profile
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string
	// PrivateJWKS contains the server JWKS with private and public information.
	// When exposing it, the private information is removed.
	PrivateJWKS             jose.JSONWebKeySet
	TokenOptions            goidc.TokenOptionsFunc
	Policies                []goidc.AuthnPolicy
	Scopes                  []goidc.Scope
	OpenIDIsRequired        bool
	GrantTypes              []goidc.GrantType
	ResponseTypes           []goidc.ResponseType
	ResponseModes           []goidc.ResponseMode
	AuthnSessionTimeoutSecs int
	ACRs                    []goidc.ACR
	DisplayValues           []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo
	// endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims             []string
	ClaimTypes         []goidc.ClaimType
	SubIdentifierTypes []goidc.SubjectIdentifierType
	StaticClients      []*goidc.Client
	// IssuerRespParamIsEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamIsEnabled bool
	// ClaimsParamIsEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamIsEnabled bool
	// TokenBindingIsRequired indicates that at least one mechanism of sender
	// contraining tokens is required, either DPoP or client TLS.
	TokenBindingIsRequired bool
	AuthorizeErrPlugin     goidc.AuthorizeErrorFunc
	// OutterAuthParamsRequired indicates that the required authorization params
	// must be informed as query parameters during the request to the
	// authorization endpoint even if they were informed previously during PAR
	// or inside JAR.
	OutterAuthParamsRequired bool
	// TODO.
	ErrLoggingFunc func(ctx goidc.Context, err error)

	Endpoint struct {
		WellKnown           string
		JWKS                string
		Token               string
		Authorize           string
		PushedAuthorization string
		DCR                 string
		UserInfo            string
		Introspection       string
		Prefix              string
	}

	Storage struct {
		Client       goidc.ClientManager
		GrantSession goidc.GrantSessionManager
		AuthnSession goidc.AuthnSessionManager
	}

	User struct {
		// DefaultSignatureKeyID defines the default key used to sign ID
		// tokens and the user info endpoint response.
		// The key can be overridden depending on the client properties
		// "id_token_signed_response_alg" and "userinfo_signed_response_alg".
		DefaultSignatureKeyID string
		// SigKeyIDs contains the IDs of the keys used to sign ID tokens
		// and the user info endpoint response.
		// There should be at most one per algorithm, in other words, there should
		// not be two key IDs that point to two keys that have the same algorithm.
		SigKeyIDs            []string
		EncIsEnabled         bool
		KeyEncAlgs           []jose.KeyAlgorithm
		DefaultContentEncAlg jose.ContentEncryption
		ContentEncAlg        []jose.ContentEncryption
		// IDTokenLifetimeSecs defines the expiry time of ID tokens.
		IDTokenLifetimeSecs int
	}

	ClientAuthn struct {
		Methods []goidc.ClientAuthnType
		// PrivateKeyJWTSigAlgs contains algorithms accepted for signing
		// client assertions during private_key_jwt.
		PrivateKeyJWTSigAlgs []jose.SignatureAlgorithm
		// ClientSecretJWTSigAlgs constains algorithms accepted for
		// signing client assertions during client_secret_jwt.
		ClientSecretJWTSigAlgs []jose.SignatureAlgorithm
		// AssertionLifetimeSecs is used to validate that the client assertions
		// will expire in the near future during private_key_jwt and
		// client_secret_jwt.
		AssertionLifetimeSecs int
	}

	DCR struct {
		IsEnabled              bool
		TokenRotationIsEnabled bool
		Plugin                 goidc.DCRFunc
	}

	Introspection struct {
		IsEnabled          bool
		ClientAuthnMethods []goidc.ClientAuthnType
	}

	RefreshToken struct {
		RotationIsEnabled bool
		LifetimeSecs      int
	}

	JARM struct {
		IsEnabled            bool
		DefaultSigKeyID      string
		SigKeyIDs            []string
		LifetimeSecs         int
		EncIsEnabled         bool
		KeyEncAlgs           []jose.KeyAlgorithm
		DefaultContentEncAlg jose.ContentEncryption
		ContentEncAlgs       []jose.ContentEncryption
	}

	JAR struct {
		IsEnabled            bool
		IsRequired           bool
		SigAlgs              []jose.SignatureAlgorithm
		LifetimeSecs         int
		EncIsEnabled         bool
		KeyEncIDs            []string
		DefaultContentEncAlg jose.ContentEncryption
		ContentEncAlgs       []jose.ContentEncryption
	}

	PAR struct {
		// IsEnabled allows client to push authorization requests.
		IsEnabled bool
		// IsRequired indicates that authorization requests can only be made if
		// they were pushed.
		IsRequired                   bool
		LifetimeSecs                 int
		AllowUnregisteredRedirectURI bool
	}

	MTLS struct {
		IsEnabled             bool
		Host                  string
		TokenBindingIsEnabled bool
		ClientCertFunc        goidc.ClientCertFunc
	}

	DPoP struct {
		IsEnabled    bool
		IsRequired   bool
		LifetimeSecs int
		SigAlgs      []jose.SignatureAlgorithm
	}

	PKCE struct {
		IsEnabled              bool
		IsRequired             bool
		DefaultChallengeMethod goidc.CodeChallengeMethod
		ChallengeMethods       []goidc.CodeChallengeMethod
	}

	AuthorizationDetails struct {
		IsEnabled bool
		Types     []string
	}

	ResourceIndicators struct {
		IsEnabled  bool // TODO.
		IsRequired bool
		Resources  []string
	}
}
