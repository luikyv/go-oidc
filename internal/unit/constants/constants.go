package constants

const Charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type AuthnStatus string

const (
	Success    AuthnStatus = "success"
	InProgress AuthnStatus = "in_progress"
	Failure    AuthnStatus = "failure"
)

const CorrelationIdKey string = "correlation_id"

type TokenModelType string

const (
	JWT    TokenModelType = "jwt"
	Opaque TokenModelType = "opaque"
)
