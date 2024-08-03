package userinfo

type userInfoResponse struct {
	JWTClaims string
	Claims    map[string]any
}
