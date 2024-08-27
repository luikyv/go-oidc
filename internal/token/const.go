package token

const (
	// RefreshTokenLength has an unusual value so to avoid refresh tokens and
	// opaque access token to be confused.
	// This happens since a refresh token is identified by its length during
	// introspection.
	RefreshTokenLength              int = 99
	defaultRefreshTokenLifetimeSecs int = 6000
)
