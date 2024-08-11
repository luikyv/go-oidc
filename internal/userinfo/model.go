package userinfo

type UserInfoResponse struct {
	JWTClaims string
	Claims    map[string]any
}
