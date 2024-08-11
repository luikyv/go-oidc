package userinfo

type Response struct {
	JWTClaims string
	Claims    map[string]any
}
