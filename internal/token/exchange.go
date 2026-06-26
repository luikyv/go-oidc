package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateExchangeToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil && (ctx.TokenExchangeClientAuthnRequired || !errors.Is(err, client.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if c == nil {
		scopeIDs := make([]string, len(ctx.Scopes))
		for i, scope := range ctx.Scopes {
			scopeIDs[i] = scope.ID
		}
		c = &goidc.Client{
			ClientMeta: goidc.ClientMeta{
				GrantTypes: []goidc.GrantType{goidc.GrantTokenExchange},
				ScopeIDs:   strings.Join(scopeIDs, " "),
			},
		}
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantTokenExchange) {
		return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the client is not allowed to use the urn:ietf:params:oauth:grant-type:token-exchange grant type"))
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, nil); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	if req.subjectToken == "" {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("subject_token is required"))
	}

	validTokenTypes := []goidc.TokenTypeIdentifier{
		goidc.TokenTypeIdentifierJWT,
		goidc.TokenTypeIdentifierAccessToken,
		goidc.TokenTypeIdentifierRefreshToken,
		goidc.TokenTypeIdentifierIDToken,
		goidc.TokenTypeIdentifierSAML1,
		goidc.TokenTypeIdentifierSAML2,
	}

	if !slices.Contains(validTokenTypes, req.subjectTokenType) {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("subject_token_type is required and must be a valid token type identifier"))
	}

	if req.actorToken != "" && !slices.Contains(validTokenTypes, req.actorTokenType) {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("actor_token_type is required when actor_token is present and must be a valid token type identifier"))
	}

	if req.requestedTokenType != "" && !slices.Contains([]goidc.TokenTypeIdentifier{
		goidc.TokenTypeIdentifierAccessToken,
		goidc.TokenTypeIdentifierRefreshToken,
		goidc.TokenTypeIdentifierIDToken,
	}, req.requestedTokenType) {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("requested_token_type must be a token type that can be issued"))
	}

	result, err := ctx.TokenExchangeHandle(goidc.TokenExchangeRequest{
		RequestedTokenType: req.requestedTokenType,
		SubjectToken:       req.subjectToken,
		SubjectTokenType:   req.subjectTokenType,
		ActorToken:         req.actorToken,
		ActorTokenType:     req.actorTokenType,
		Audience:           req.audience,
		Resource:           req.resources,
	})
	if err != nil {
		return response{}, fmt.Errorf("could not handle token exchange: %w", err)
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:                 goidc.GrantTokenExchange,
		Subject:              result.Subject,
		Actor:                result.Actor,
		Store:                result.Store,
		ClientID:             c.ID,
		Scopes:               req.scopes,
		AuthDetails:          req.authDetails,
		Resources:            req.resources,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	})
	if err != nil {
		return response{}, err
	}

	switch req.requestedTokenType {
	case goidc.TokenTypeIdentifierIDToken:
		idToken, err := MakeIDToken(ctx, c, IDTokenOptions{
			Subject: grant.Subject,
			Nonce:   grant.AuthParams.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the token exchange grant: %w", err)
		}
		return response{
			AccessToken:     idToken,
			IssuedTokenType: goidc.TokenTypeIdentifierIDToken,
			ExpiresIn:       ctx.IDTokenLifetimeSecs,
			TokenType:       goidc.TokenTypeNotApplicable,
		}, nil
	case goidc.TokenTypeIdentifierRefreshToken:
		return response{
			AccessToken:          grant.RefreshToken,
			IssuedTokenType:      goidc.TokenTypeIdentifierRefreshToken,
			ExpiresIn:            ctx.RefreshTokenLifetimeSecs,
			TokenType:            goidc.TokenTypeNotApplicable,
			Scopes:               grant.Scopes,
			AuthorizationDetails: grant.AuthDetails,
			Resources:            grant.Resources,
		}, nil
	default:
		tkn, tokenValue, err := Issue(ctx, grant, c, nil)
		if err != nil {
			return response{}, err
		}
		return response{
			AccessToken:          tokenValue,
			IssuedTokenType:      goidc.TokenTypeIdentifierAccessToken,
			ExpiresIn:            tkn.LifetimeSecs(),
			TokenType:            tkn.Type,
			AuthorizationDetails: tkn.AuthDetails,
			Resources:            tkn.Resources,
			Scopes:               tkn.Scopes,
		}, nil
	}
}
