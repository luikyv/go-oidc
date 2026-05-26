package token

import (
	"errors"
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
	subType := ctx.SubIdentifierTypeDefault
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}
	if tknOpts.Format == goidc.TokenFormatJWT && subType == goidc.SubIdentifierPairwise && grant.Subject != grant.ClientID {
		tknOpts = goidc.NewOpaqueTokenOptions(tknOpts.LifetimeSecs)
	}

	if !ctx.OpaqueTokenIsEnabled && tknOpts.Format == goidc.TokenFormatOpaque {
		return nil, "", errors.New("opaque tokens are not enabled")
	}

	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		GrantID:        grant.ID,
		Subject:        grant.Subject,
		ClientID:       grant.ClientID,
		Scopes:         grant.Scopes,
		AuthDetails:    grant.AuthDetails,
		Resources:      grant.Resources,
		JWKThumbprint:  grant.JWKThumbprint,
		CertThumbprint: grant.CertThumbprint,
		CreatedAt:      now,
		ExpiresAt:      now + tknOpts.LifetimeSecs,
		Format:         tknOpts.Format,
		SigAlg:         tknOpts.JWTSigAlg,
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

	var tokenValue string
	switch tknOpts.Format {
	case goidc.TokenFormatOpaque:
		tkn.ID = ctx.OpaqueTokenValue(grant)
		tokenValue = tkn.ID
	case goidc.TokenFormatJWT:
		tkn.ID = ctx.JWTID()

		claims := map[string]any{
			goidc.ClaimTokenID:  tkn.ID,
			goidc.ClaimGrantID:  grant.ID,
			goidc.ClaimIssuer:   ctx.Issuer(),
			goidc.ClaimSubject:  tkn.Subject,
			goidc.ClaimScope:    tkn.Scopes,
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   tkn.ExpiresAt,
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

		signed, err := ctx.Sign(claims, tkn.SigAlg, (&jose.SignerOptions{}).WithType("at+jwt"))
		if err != nil {
			return nil, "", fmt.Errorf("could not sign the access token: %w", err)
		}

		tokenValue = signed
	}

	if err := ctx.HandleToken(tkn, grant); err != nil {
		return nil, "", err
	}
	if tkn.Format == goidc.TokenFormatOpaque {
		if err := ctx.SaveOpaqueToken(tkn); err != nil {
			return nil, "", err
		}
	}

	return tkn, tokenValue, nil
}

func MakeIDToken(ctx oidc.Context, c *goidc.Client, opts IDTokenOptions) (string, error) {
	alg := ctx.IDTokenDefaultSigAlg
	if c.IDTokenSigAlg != "" && slices.Contains(ctx.IDTokenSigAlgs, c.IDTokenSigAlg) {
		alg = c.IDTokenSigAlg
	}

	subType := ctx.SubIdentifierTypeDefault
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
	}

	if opts.Nonce != "" {
		claims[goidc.ClaimNonce] = opts.Nonce
	}

	if opts.AuthReqID != "" {
		claims[goidc.ClaimAuthReqID] = opts.AuthReqID
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
		return "", fmt.Errorf("could not resolve an encryption key for the id token: %w", err)
	}

	contentEncAlg := ctx.IDTokenDefaultContentEncAlg
	if c.IDTokenContentEncAlg != "" && slices.Contains(ctx.IDTokenContentEncAlgs, c.IDTokenContentEncAlg) {
		contentEncAlg = c.IDTokenContentEncAlg
	}

	encIDToken, err := joseutil.Encrypt(idToken, jwk, contentEncAlg)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the id token: %w", err)
	}
	return encIDToken, nil
}

func generateToken(ctx oidc.Context, req request) (response, error) {
	if !slices.Contains(ctx.GrantTypes, req.grantType) {
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	switch req.grantType {
	case goidc.GrantClientCredentials:
		return generateClientCredentialsToken(ctx, req)
	case goidc.GrantAuthorizationCode:
		return generateAuthCodeToken(ctx, req)
	case goidc.GrantRefreshToken:
		return generateRefreshToken(ctx, req)
	case goidc.GrantJWTBearer:
		return generateJWTBearerToken(ctx, req)
	case goidc.GrantCIBA:
		return generateCIBAToken(ctx, req)
	case goidc.GrantPreAuthorizedCode:
		return generatePreAuthCodeToken(ctx, req)
	case goidc.GrantDeviceCode:
		return generateDeviceCodeToken(ctx, req)
	default:
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}
}
