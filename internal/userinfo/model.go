package userinfo

type response struct {
	jwtClaims string
	claims    map[string]any
}
