package token

import (
	"fmt"
	"maps"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

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
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		AuthDetails:          grant.AuthDetails,
		Resources:            grant.Resources,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + tknOpts.LifetimeSecs,
		Format:               tknOpts.Format,
		SigAlg:               tknOpts.JWTSigAlg,
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
	if tkn.ClientCertThumbprint != "" {
		confirmation["x5t#S256"] = tkn.ClientCertThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	maps.Copy(claims, ctx.TokenClaims(grant))

	accessToken, err := ctx.Sign(claims, tkn.SigAlg, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return "", fmt.Errorf("could not sign the access token: %w", err)
	}

	return accessToken, nil
}
