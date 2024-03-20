package models

type AuthnSession struct {
	Id                string
	CallbackId        string
	StepId            string
	ClientId          string
	Scopes            []string
	RedirectUri       string
	State             string
	AuthorizationCode string
	Subject           string
	ErrorDescription  string
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

func (session *AuthnSession) SetError(errorDescription string) {
	session.ErrorDescription = errorDescription
}
