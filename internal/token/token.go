package token

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ExtractID returns the ID of an access token.
// If it's a JWT, the ID is the the "jti" claim. Otherwise, the token is
// considered opaque and its ID is the thumbprint of the token.
func ExtractID(ctx oidc.Context, token string) (string, error) {
	if !joseutil.IsJWS(token) {
		return token, nil
	}

	claims, err := validClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenID := claims[goidc.ClaimTokenID]
	if tokenID == nil {
		return "", goidc.WrapError(goidc.ErrorCodeAccessDenied, "invalid token", errors.New("token id was not found in the claims"))
	}

	if _, ok := tokenID.(string); !ok {
		return "", goidc.WrapError(goidc.ErrorCodeAccessDenied, "invalid token", errors.New("token id is not a string"))
	}

	return tokenID.(string), nil
}

type IssuanceOptions struct {
	Scopes      string
	AuthDetails []goidc.AuthDetail
	Resources   goidc.Resources
}

// Issue creates a new access token for the grant, persists both the grant and
// token, and returns the token and its serialized value.
func Issue(ctx oidc.Context, grant *goidc.Grant, c *goidc.Client, opts *IssuanceOptions) (*goidc.Token, string, error) {
	if opts == nil {
		opts = &IssuanceOptions{}
	}

	tknOpts := ctx.TokenOptions(grant, c)
	// Use an opaque token format if the subject identifier type is pairwise.
	// This prevents potential information leakage that could occur if the JWT token was decoded by clients.
	subType := ctx.DefaultSubIdentifierType
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}
	if tknOpts.Format == goidc.TokenFormatJWT && subType == goidc.SubIdentifierPairwise && grant.Type != goidc.GrantClientCredentials {
		tknOpts = goidc.NewOpaqueTokenOptions(tknOpts.LifetimeSecs)
	}

	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		GrantID:            grant.ID,
		Subject:            grant.Subject,
		ClientID:           grant.ClientID,
		Scopes:             grant.Scopes,
		AuthDetails:        grant.AuthDetails,
		Resources:          grant.Resources,
		JWKThumbprint:      grant.JWKThumbprint,
		CertThumbprint:     grant.CertThumbprint,
		CreatedAtTimestamp: now,
		ExpiresAtTimestamp: now + tknOpts.LifetimeSecs,
		Format:             tknOpts.Format,
		SigAlg:             tknOpts.JWTSigAlg,
	}
	if tknOpts.Format == goidc.TokenFormatOpaque {
		tkn.ID = ctx.OpaqueToken()
	} else {
		tkn.ID = ctx.JWTID()
	}
	if tkn.JWKThumbprint != "" {
		tkn.Type = goidc.TokenTypeDPoP
	} else {
		tkn.Type = goidc.TokenTypeBearer
	}
	if opts.Scopes != "" {
		tkn.Scopes = opts.Scopes
	}
	if ctx.RARIsEnabled && opts.AuthDetails != nil {
		tkn.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsIsEnabled && opts.Resources != nil {
		tkn.Resources = opts.Resources
	}

	tokenValue, err := makeAccessToken(ctx, tkn, grant)
	if err != nil {
		return nil, "", err
	}
	if grant.ExpiresAtTimestamp == 0 {
		grant.ExpiresAtTimestamp = tkn.ExpiresAtTimestamp
	}
	if err := ctx.HandleToken(tkn, grant); err != nil {
		return nil, "", err
	}
	if err := ctx.SaveGrant(grant); err != nil {
		return nil, "", err
	}
	if err := ctx.SaveToken(tkn); err != nil {
		return nil, "", err
	}

	return tkn, tokenValue, nil
}

func MakeIDToken(ctx oidc.Context, c *goidc.Client, opts IDTokenOptions) (string, error) {
	alg := ctx.IDTokenDefaultSigAlg
	if c.IDTokenSigAlg != "" && slices.Contains(ctx.IDTokenSigAlgs, c.IDTokenSigAlg) {
		alg = c.IDTokenSigAlg
	}

	subType := ctx.DefaultSubIdentifierType
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}

	sub := opts.Subject
	if subType == goidc.SubIdentifierPairwise {
		sub = ctx.PairwiseSubject(opts.Subject, c)
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimSubject:  sub,
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	// Avoid an empty client ID claim for anonymous clients.
	if c.ID != "" {
		claims[goidc.ClaimAudience] = c.ID
	}

	if alg != goidc.None {
		if opts.AccessToken != "" {
			claims[goidc.ClaimAccessTokenHash] = hashutil.HalfHash(opts.AccessToken, alg)
		}

		if opts.AuthorizationCode != "" {
			claims[goidc.ClaimAuthzCodeHash] = hashutil.HalfHash(opts.AuthorizationCode, alg)
		}

		if opts.State != "" {
			claims[goidc.ClaimStateHash] = hashutil.HalfHash(opts.State, alg)
		}

		if opts.RefreshToken != "" {
			claims[goidc.ClaimRefreshTokenHash] = hashutil.HalfHash(opts.RefreshToken, alg)
		}

		if opts.AuthReqID != "" {
			claims[goidc.ClaimAuthReqID] = hashutil.HalfHash(opts.AuthReqID, alg)
		}
	}

	if opts.Nonce != "" {
		claims[goidc.ClaimNonce] = opts.Nonce
	}

	maps.Copy(claims, opts.Claims)

	idToken, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the id token: %w", err)
	}

	// If encryption is disabled, just return the signed ID token.
	if !ctx.IDTokenEncIsEnabled || c.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	jwk, err := client.JWKByAlg(ctx, c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not encrypt the id token", err)
	}

	contentEncAlg := ctx.IDTokenDefaultContentEncAlg
	if c.IDTokenContentEncAlg != "" && slices.Contains(ctx.IDTokenContentEncAlgs, c.IDTokenContentEncAlg) {
		contentEncAlg = c.IDTokenContentEncAlg
	}

	encIDToken, err := joseutil.Encrypt(idToken, jwk, contentEncAlg)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not encrypt the id token", err)
	}
	return encIDToken, nil
}

// makeAccessToken generates an access token value. It returns the JWT or opaque string.
func makeAccessToken(ctx oidc.Context, tkn *goidc.Token, grant *goidc.Grant) (string, error) {
	if tkn.Format == goidc.TokenFormatOpaque {
		return tkn.ID, nil
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimTokenID:  tkn.ID,
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimSubject:  tkn.Subject,
		goidc.ClaimScope:    tkn.Scopes,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   tkn.ExpiresAtTimestamp,
	}

	if tkn.ClientID != "" {
		claims[goidc.ClaimClientID] = tkn.ClientID
	}

	if tkn.AuthDetails != nil {
		claims[goidc.ClaimAuthDetails] = tkn.AuthDetails
	}

	if tkn.Resources != nil {
		claims[goidc.ClaimAudience] = tkn.Resources
	}

	confirmation := make(map[string]string)
	if tkn.JWKThumbprint != "" {
		confirmation["jkt"] = tkn.JWKThumbprint
	}
	if tkn.CertThumbprint != "" {
		confirmation["x5t#S256"] = tkn.CertThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	maps.Copy(claims, ctx.TokenClaims(tkn, grant))

	accessToken, err := ctx.Sign(claims, tkn.SigAlg, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return "", fmt.Errorf("could not sign the access token: %w", err)
	}

	return accessToken, nil
}

// validClaims verifies a token and returns its claims.
func validClaims(ctx oidc.Context, token string) (map[string]any, error) {
	algs, err := ctx.SigAlgs()
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.ParseSigned(token, algs)
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not parse the token", err)
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid header kid")
	}

	keyID := parsedToken.Headers[0].KeyID
	publicKey, err := ctx.PublicJWK(keyID)
	if err != nil || publicKey.Use != string(goidc.KeyUsageSignature) {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "invalid token", err)
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.Key, &claims, &rawClaims); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied,
			"invalid token", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Issuer(),
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "invalid token", err)
	}

	return rawClaims, nil
}

func generateGrant(ctx oidc.Context, req request) (tokenResp response, err error) {

	if !slices.Contains(ctx.GrantTypes, req.grantType) {
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	switch req.grantType {
	case goidc.GrantClientCredentials:
		return generateClientCredentialsGrant(ctx, req)
	case goidc.GrantAuthorizationCode:
		return generateAuthCodeGrant(ctx, req)
	case goidc.GrantRefreshToken:
		return generateRefreshTokenGrant(ctx, req)
	case goidc.GrantJWTBearer:
		return generateJWTBearerGrant(ctx, req)
	case goidc.GrantCIBA:
		return generateCIBAGrant(ctx, req)
	case goidc.GrantPreAuthorizedCode:
		return generatePreAuthCodeGrant(ctx, req)
	default:
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}
}
