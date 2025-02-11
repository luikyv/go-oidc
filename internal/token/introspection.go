package token

import (
	"errors"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(ctx oidc.Context, req queryRequest) (goidc.TokenInfo, error) {
	c, err := clientutil.Authenticated(ctx, clientutil.TokenIntrospectionAuthnContext)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateIntrospectionRequest(req); err != nil {
		return goidc.TokenInfo{}, err
	}

	// The information of an invalid token must not be sent as an error.
	// It will be returned as the default value of [goidc.TokenInfo] with the
	// field is_active as false.
	tokenInfo, err := IntrospectionInfo(ctx, req.token)
	if err != nil {
		ctx.NotifyError(err)
	}

	if !ctx.IsClientAllowedTokenIntrospection(c, tokenInfo) {
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeAccessDenied,
			"client not allowed to introspect the token")
	}

	return tokenInfo, nil
}

func validateIntrospectionRequest(req queryRequest) error {
	if req.token == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token is missing")
	}
	return nil
}

func IntrospectionInfo(ctx oidc.Context, accessToken string) (goidc.TokenInfo, error) {

	if joseutil.IsJWS(accessToken) {
		return jwtTokenInfo(ctx, accessToken)
	}

	if len(accessToken) == goidc.RefreshTokenLength {
		return refreshTokenInfo(ctx, accessToken)
	}

	return opaqueTokenInfo(ctx, accessToken)
}

func refreshTokenInfo(
	ctx oidc.Context,
	token string,
) (
	goidc.TokenInfo,
	error,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(token)
	if err != nil {
		return goidc.TokenInfo{},
			errors.New("token not found")
	}

	if grantSession.IsExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" ||
		grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        grantSession.JWKThumbprint,
			ClientCertThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Subject:               grantSession.Subject,
		Type:                  goidc.TokenHintRefresh,
		Scopes:                grantSession.GrantedScopes,
		AuthorizationDetails:  grantSession.GrantedAuthDetails,
		ClientID:              grantSession.ClientID,
		ExpiresAtTimestamp:    grantSession.ExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.GrantedResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}

func jwtTokenInfo(ctx oidc.Context, accessToken string) (goidc.TokenInfo, error) {
	claims, err := validClaims(ctx, accessToken)
	if err != nil || claims[goidc.ClaimTokenID] == nil {
		return goidc.TokenInfo{}, errors.New("invalid token")
	}

	return tokenIntrospectionInfoByID(ctx, claims[goidc.ClaimTokenID].(string))
}

func opaqueTokenInfo(ctx oidc.Context, token string) (goidc.TokenInfo, error) {
	// The tokens generated by this implementation are intentionally not UUIDs.
	// This design choice ensures that the 'jti' claim from a JWT cannot be
	// directly used as the token value, preventing potential misuse or confusion.
	//
	// If the provided token is mistakenly in a valid UUID format, the function
	// returns an error to indicate an invalid token.
	if uuid.Validate(token) == nil {
		return goidc.TokenInfo{}, errors.New("invalid token")
	}
	return tokenIntrospectionInfoByID(ctx, token)
}

func tokenIntrospectionInfoByID(ctx oidc.Context, tokenID string) (goidc.TokenInfo, error) {
	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return goidc.TokenInfo{}, errors.New("token not found")
	}

	if grantSession.HasLastTokenExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        grantSession.JWKThumbprint,
			ClientCertThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Subject:               grantSession.Subject,
		Type:                  goidc.TokenHintAccess,
		Scopes:                grantSession.ActiveScopes,
		AuthorizationDetails:  grantSession.ActiveAuthDetails,
		ClientID:              grantSession.ClientID,
		ExpiresAtTimestamp:    grantSession.LastTokenExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.ActiveResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}
