package models

type AuthnSession struct {
	Id                string
	CallbackId        string
	StepId            string
	ClientId          string
	RequestUri        string
	Scopes            []string
	RedirectUri       string
	State             string
	AuthorizationCode string
	Subject           string
	ErrorDescription  string
	Store             map[string]string // Allow the developer to store information in memory and, hence, between steps.
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

func (session *AuthnSession) SetError(errorDescription string) {
	session.ErrorDescription = errorDescription
}

func (session *AuthnSession) SaveParameter(key string, value string) {
	session.Store[key] = value
}

func (session *AuthnSession) GetParameter(key string, value string) string {
	return session.Store[key]
}
