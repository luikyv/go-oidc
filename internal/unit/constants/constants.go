package constants

type AuthnStatus string

const (
	Success    AuthnStatus = "success"
	InProgress AuthnStatus = "in_progress"
	Failure    AuthnStatus = "failure"
)
