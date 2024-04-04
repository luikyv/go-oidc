package constants

import "github.com/go-jose/go-jose/v4"

const CallbackIdLength int = 20

const RequestUriLength int = 20

const PARLifetimeSecs int = 60

const AuthorizationCodeLifetimeSecs int = 60

const AuthorizationCodeLength int = 30

const RefreshTokenLength int = 30

var ClientSigningAlgorithms []jose.SignatureAlgorithm = []jose.SignatureAlgorithm{
	jose.RS256,
}
