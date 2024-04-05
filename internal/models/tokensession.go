package models

type TokenSession struct {
	Id                 string
	TokenModelId       string
	Token              string
	IdToken            string
	RefreshToken       string
	ExpiresInSecs      int
	CreatedAtTimestamp int
	Subject            string
	ClientId           string
	Scopes             []string
	AdditionalClaims   map[string]string
}
