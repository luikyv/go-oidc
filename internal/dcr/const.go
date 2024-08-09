package dcr

const (
	dynamicClientIDLength int = 30
	// clientSecretLength must be at least 64 characters, so that it can be also
	// used for symmetric encryption during, for instance, authentication with
	// client_secret_jwt.
	// For client_secret_jwt, the highest algorithm we accept is HS512 which
	// requires a key of at least 512 bits (64 characters).
	clientSecretLength            int = 64
	registrationAccessTokenLength int = 50
)
