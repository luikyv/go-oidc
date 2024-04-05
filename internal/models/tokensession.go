package models

type TokenSession struct {
	Id                    string
	TokenModelId          string
	TokenId               string
	Token                 string
	IdToken               string
	RefreshToken          string
	ExpiresInSecs         int
	RefreshTokenExpiresIn int
	CreatedAtTimestamp    int
	Subject               string
	ClientId              string
	Scopes                []string
	AdditionalClaims      map[string]string
}
