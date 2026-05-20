package vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Request struct {
	Scopes    string
	Details   []goidc.AuthDetail
	Resources goidc.Resources
}

// Resolve validates all VC signals (auth details, scopes, resources) for
// internal consistency, then resolves the VC issuer and credential
// configuration IDs.
func Resolve(ctx oidc.Context, req Request) (goidc.VCIssuer, []goidc.VCConfigurationID, error) {
	var issuer goidc.VCIssuer
	credentials := make(map[goidc.VCConfigurationID]struct{})

	if len(ctx.VCIssuers) == 1 {
		issuer = ctx.VCIssuers[0]
	}

	if ctx.RARIsEnabled {
		for _, detail := range req.Details {
			if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
				continue
			}

			credIDRaw, ok := detail["credential_configuration_id"]
			if !ok {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					fmt.Errorf("credential_configuration_id is required for %s", goidc.AuthDetailTypeOpenIDCredential))
			}
			credID, ok := credIDRaw.(string)
			if !ok {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					fmt.Errorf("credential_configuration_id for %s must be a string", goidc.AuthDetailTypeOpenIDCredential))
			}

			locs := detail.Locations()
			switch len(locs) {
			case 0:
				if len(ctx.VCIssuers) > 1 {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
						errors.New("the credential issuer could not be determined from the authorization details"))
				}
			case 1:
				if issuer.ID == "" {
					iss, ok := ctx.VCIssuer(locs[0])
					if !ok {
						return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
							errors.New("the authorization detail references an unknown credential issuer"))
					}
					issuer = iss
				}
				if locs[0] != issuer.ID {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
						errors.New("all openid_credential authorization details must reference the same issuer"))
				}
			default:
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					errors.New("openid_credential authorization details must contain at most one location"))
			}

			if _, exists := issuer.Configurations[goidc.VCConfigurationID(credID)]; !exists {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					errors.New("the authorization detail references an unknown credential configuration"))
			}

			credentials[goidc.VCConfigurationID(credID)] = struct{}{}
		}
	}

	if req.Scopes != "" {
		for s := range strings.FieldsSeq(req.Scopes) {
			for _, iss := range ctx.VCIssuers {
				for configID, config := range iss.Configurations {
					if config.Scope.ID != "" && config.Scope.ID == s {
						if issuer.ID == "" {
							issuer = iss
						}
						if iss.ID != issuer.ID {
							return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope",
								errors.New("the requested VC scopes resolve to different issuers"))
						}
						credentials[configID] = struct{}{}
					}
				}
			}
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		for _, resource := range req.Resources {
			if iss, ok := ctx.VCIssuer(resource); ok {
				if issuer.ID == "" {
					issuer = iss
				}
				if iss.ID != issuer.ID {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope",
						errors.New("the requested VC signals resolve to different issuers"))
				}
			}
		}
	}

	if len(credentials) == 0 {
		return goidc.VCIssuer{}, nil, nil
	}

	configIDs := make([]goidc.VCConfigurationID, 0, len(credentials))
	for id := range credentials {
		configIDs = append(configIDs, id)
	}
	return issuer, configIDs, nil
}

type offerResponse struct {
	Issuer           string                    `json:"credential_issuer"`
	ConfigurationIDs []goidc.VCConfigurationID `json:"credential_configuration_ids"`
	Grants           goidc.VCOfferGrants       `json:"grants,omitzero"`
}

func offer(ctx oidc.Context, id string) (offerResponse, error) {
	offer, err := ctx.VCOffer(id)
	if err != nil {
		return offerResponse{}, err
	}

	return offerResponse{
		Issuer:           ctx.VCIssuers[0].ID,
		ConfigurationIDs: offer.ConfigurationIDs,
		Grants:           offer.Grants,
	}, nil
}

func CreateOffer(ctx oidc.Context, opts goidc.VCOfferOptions) (string, error) {
	now := timeutil.TimestampNow()
	offer := &goidc.VCOffer{
		ID:                 ctx.VCOfferID(),
		ConfigurationIDs:   opts.ConfigurationIDs,
		CreatedAtTimestamp: now,
	}

	if opts.GrantAuthCode != nil {
		offer.Grants.AuthCode = &goidc.VCOfferGrantAuthCode{
			IssuerState: opts.GrantAuthCode.IssuerState,
			AuthServer:  opts.GrantAuthCode.AuthServer,
		}
	}

	if opts.GrantPreAuthCode != nil {
		offer.Grants.PreAuthCode = &goidc.VCOfferGrantPreAuthCode{
			Code:       opts.GrantPreAuthCode.Code,
			TxCode:     opts.GrantPreAuthCode.TxCode,
			AuthServer: opts.GrantPreAuthCode.AuthServer,
		}
	}

	if err := ctx.VCSaveOffer(offer); err != nil {
		return "", err
	}

	if opts.ByReference {
		return "openid-credential-offer://?credential_offer_uri=" + ctx.VCIssuers[0].ID + ctx.VCOfferEndpoint + "/" + offer.ID, nil
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("could not marshal offer: %w", err)
	}

	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), nil
}
